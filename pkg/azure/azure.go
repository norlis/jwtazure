package azure

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/norlis/httpgate/pkg/kit/problem"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

var (
	ErrMissingAuthHeader       = errors.New("authorization header is required")
	ErrInvalidAuthHeaderFormat = errors.New("authorization header format must be 'Bearer {token}'")
	ErrTokenParsingFailed      = errors.New("failed to parse token")
	ErrTokenInvalid            = errors.New("token is invalid (possibly expired or not yet active)")
	ErrInvalidIssuer           = errors.New("invalid token issuer")
	ErrInvalidAudience         = errors.New("invalid token audience")
)

// =============================================================================
// Estructuras de Datos y Claves de Contexto
// =============================================================================

// userClaimsKey es el tipo para la clave de contexto. Usar un tipo struct{}
// sin exportar previene colisiones con otras claves de contexto en la aplicación.
type userClaimsKey struct{}

// UserClaims contiene las notificaciones validadas del token para un uso seguro.
type UserClaims struct {
	Subject       string
	Name          string
	PreferredUser string
	TenantID      string
	Audience      jwt.ClaimStrings
	Issuer        string
	Scopes        string
	Roles         []string
	RawClaims     jwt.MapClaims
}

// Validator encapsula la configuración y la lógica para validar tokens de Azure AD.
type Validator struct {
	jwksV1                 keyfunc.Keyfunc
	jwksV2                 keyfunc.Keyfunc
	validIssuers           []string
	validAudiences         []string
	isAudienceCheckEnabled bool
	logger                 *zap.Logger
}

// Option es una función que configura un Validator.
type Option func(*Validator)

// WithAudiences establece las audiencias válidas para el token.
func WithAudiences(audiences ...string) Option {
	return func(v *Validator) {
		v.validAudiences = audiences
	}
}

// WithoutAudienceValidation deshabilita la comprobación de la audiencia.
// ¡Usar con precaución! Generalmente no se recomienda en producción.
func WithoutAudienceValidation() Option {
	return func(v *Validator) {
		v.isAudienceCheckEnabled = false
	}
}

// WithLogger inyecta un logger zap para el registro estructurado.
func WithLogger(logger *zap.Logger) Option {
	return func(v *Validator) {
		v.logger = logger
	}
}

// NewValidator crea un nuevo validador de tokens configurado con las opciones proporcionadas.
// Inicia la obtención y el cacheo en segundo plano de los JWKS de Azure.
func NewValidator(ctx context.Context, tenantID string, opts ...Option) (*Validator, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("el ID de inquilino (tenantID) no puede estar vacío")
	}

	jwksV1URL := fmt.Sprintf("https://login.microsoftonline.com/%s/discovery/keys", tenantID)
	jwksV2URL := fmt.Sprintf("https://login.microsoftonline.com/%s/discovery/v2.0/keys", tenantID)

	// La librería `keyfunc` maneja internamente el almacenamiento (storage) y la
	// actualización de las claves públicas de forma automática. Al llamar a
	// NewDefaultCtx, se inicia una gorutina en segundo plano que refresca
	// periódicamente el JWKS desde la URL de Azure. El `context` (ctx) que
	// se pasa a la función controla el ciclo de vida de esta gorutina,
	// permitiendo un apagado elegante.
	jwksV1, err := keyfunc.NewDefaultCtx(ctx, []string{jwksV1URL})
	if err != nil {
		return nil, fmt.Errorf("fallo al crear el JWKS para v1: %w", err)
	}

	jwksV2, err := keyfunc.NewDefaultCtx(ctx, []string{jwksV2URL})
	if err != nil {
		return nil, fmt.Errorf("fallo al crear el JWKS para v2: %w", err)
	}

	validator := &Validator{
		jwksV1:                 jwksV1,
		jwksV2:                 jwksV2,
		isAudienceCheckEnabled: true, // Habilitado por defecto
		validIssuers: []string{
			fmt.Sprintf("https://sts.windows.net/%s/", tenantID),
			fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", tenantID),
		},
	}

	// Aplicar todas las opciones de configuración proporcionadas.
	for _, opt := range opts {
		opt(validator)
	}

	// Si no se proporciona un logger, crear uno de producción por defecto.
	if validator.logger == nil {
		prodLogger, err := zap.NewProduction()
		if err != nil {
			return nil, fmt.Errorf("fallo al crear el logger por defecto: %w", err)
		}
		validator.logger = prodLogger
	}

	if validator.isAudienceCheckEnabled && len(validator.validAudiences) == 0 {
		return nil, fmt.Errorf("la validación de audiencia está habilitada pero no se proporcionaron audiencias válidas")
	}

	return validator, nil
}

// =============================================================================
// Middleware HTTP
// =============================================================================

// Middleware devuelve un manejador de middleware HTTP que valida el token de portador.
func (v *Validator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString, err := extractBearerToken(r)
		if err != nil {
			problem.RespondError(w,
				problem.FromError(
					err,
					http.StatusUnauthorized,
					problem.WithInstance(r),
				),
			)
			return
		}

		claims, err := v.validateToken(tokenString)
		if err != nil {
			v.logger.Warn("Token validation failed", zap.Error(err), zap.String("remote_addr", r.RemoteAddr))
			problem.RespondError(w,
				problem.FromError(
					ErrTokenInvalid,
					http.StatusUnauthorized,
					problem.WithInstance(r),
				),
			)

			return
		}

		// TODO cambiar a debug
		v.logger.Info("Token validated", zap.Any("claims", claims))
		ctxWithClaims := context.WithValue(r.Context(), userClaimsKey{}, claims)
		next.ServeHTTP(w, r.WithContext(ctxWithClaims))
	})
}

// extractBearerToken extracts the JWT from the Authorization header,
// handling the "Bearer" scheme in a case-insensitive manner as per RFC 6750.
// TODO valorar usar
// tokenString, found := strings.CutPrefix(authHeader, "Bearer ")
func extractBearerToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", ErrMissingAuthHeader
	}

	// The "Bearer" scheme is case-insensitive. Check for "Bearer " prefix.
	if len(authHeader) > 7 && strings.EqualFold(authHeader[:7], "Bearer ") {
		return authHeader[7:], nil
	}

	return "", ErrInvalidAuthHeaderFormat
}

// validateToken realiza el proceso completo de validación del token.
func (v *Validator) validateToken(tokenString string) (*UserClaims, error) {
	var mapClaims jwt.MapClaims
	token, err := jwt.ParseWithClaims(tokenString, &mapClaims, v.keyFunc, jwt.WithValidMethods([]string{"RS256"}))
	if err != nil {
		// Envolvemos el error original para mantener el contexto completo.
		return nil, fmt.Errorf("%w: %v", ErrTokenParsingFailed, err)
	}

	if !token.Valid {
		return nil, ErrTokenInvalid
	}

	// Validar emisor
	issuer, _ := mapClaims.GetIssuer()
	if !slices.Contains(v.validIssuers, issuer) {
		return nil, fmt.Errorf("%w. Received: %s", ErrInvalidIssuer, issuer)
	}

	// Validar audiencia (si está habilitado)
	if v.isAudienceCheckEnabled {
		audience, _ := mapClaims.GetAudience()
		if !audiencesIntersect(v.validAudiences, audience) {
			return nil, fmt.Errorf("%w. Received: %v", ErrInvalidAudience, audience)
		}
	}

	return v.buildUserClaims(mapClaims), nil
}

// keyFunc es la función que provee la clave de verificación a la librería JWT.
func (v *Validator) keyFunc(token *jwt.Token) (interface{}, error) {
	key, err := v.jwksV2.Keyfunc(token)
	if err == nil {
		return key, nil
	}
	return v.jwksV1.Keyfunc(token)
}

// buildUserClaims construye la struct UserClaims a partir del mapa de notificaciones crudas.
// Esta función está diseñada para manejar de forma segura las diferencias entre los tokens
// de usuario (delegados) y los tokens de aplicación (client credentials).
func (v *Validator) buildUserClaims(mapClaims jwt.MapClaims) *UserClaims {
	aud, _ := mapClaims.GetAudience()
	iss, _ := mapClaims.GetIssuer()
	sub, _ := mapClaims.GetSubject()

	// Extracción segura de roles (típicamente para tokens de aplicación).
	var roles []string
	if rolesClaim, ok := mapClaims["roles"]; ok {
		if rolesInterfaces, ok := rolesClaim.([]interface{}); ok {
			for _, roleInterface := range rolesInterfaces {
				if role, ok := roleInterface.(string); ok {
					roles = append(roles, role)
				}
			}
		}
	}

	// Extracción segura de otros campos. Se utilizan aserciones de tipo seguras
	// porque estos claims pueden no estar presentes en todos los tipos de token.
	// Por ejemplo, `name` y `preferred_username` están en tokens de usuario,
	// mientras que `scp` (scopes) es para permisos delegados de usuario y `roles`
	// es para permisos de aplicación.
	name, _ := mapClaims["name"].(string)
	preferredUser, _ := mapClaims["preferred_username"].(string)
	tenantID, _ := mapClaims["tid"].(string)
	scopes, _ := mapClaims["scp"].(string)

	return &UserClaims{
		Subject:       sub,
		Name:          name,
		PreferredUser: preferredUser,
		TenantID:      tenantID,
		Audience:      aud,
		Issuer:        iss,
		Scopes:        scopes,
		Roles:         roles,
		RawClaims:     mapClaims,
	}
}

// audiencesIntersect verifica si alguna de las audiencias del token es válida.
func audiencesIntersect(validAudiences []string, tokenAudiences jwt.ClaimStrings) bool {
	for _, tokenAud := range tokenAudiences {
		if slices.Contains(validAudiences, tokenAud) {
			return true
		}
	}
	return false
}

// GetClaimsFromContext recupera las notificaciones del usuario del contexto de una manera segura.
func GetClaimsFromContext(ctx context.Context) (*UserClaims, bool) {
	claims, ok := ctx.Value(userClaimsKey{}).(*UserClaims)
	return claims, ok
}
