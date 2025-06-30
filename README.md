# Middleware de Autenticación Go para Tokens de Azure AD


Middleware net/http para Go, diseñado para validar tokens de acceso (v1.0 y v2.0) emitidos por Microsoft Entra ID (Azure AD). 


## Descripción General
El middleware intercepta las peticiones HTTP entrantes, extrae el token de portador (Bearer Token) de la cabecera Authorization y realiza un proceso de validación completo. Si el token es válido, inyecta los claims del usuario en el contexto de la petición de forma segura; de lo contrario, rechaza la petición con un error 401 Unauthorized.

## Reequisitos
- `Go 1.21` o superior.
- Variables `TenantId` & `audiences`

## Uso Básico

```go
package main

import (
	"context"
	"net/http"
	"os"
	"strings"

	"github.com/norlis/jwtazure/pkg/azure"
	"go.uber.org/zap"
)

func main() {
	logger, _ := zap.NewProduction()
	defer logger.Sync()
	ctx := context.Background()

	tenantID := os.Getenv("AZURE_TENANT_ID")
	audiences := strings.Split(os.Getenv("AZURE_AUDIENCES"), ",")

	azureValidator, err := azure.NewValidator(
		ctx,
		tenantID,
		azure.WithAudiences(
			audiences...,
		),
		azure.WithLogger(logger),
		// Ej: Deshabilitar la validación de audiencia si es necesario
		// WithoutAudienceValidation(),
	)
	if err != nil {
		logger.Fatal("Fallo al crear el validador", zap.Error(err))
	}

	myProtectedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Obtener los claims del contexto de forma segura.
		claims, ok := azure.GetClaimsFromContext(r.Context())
		if !ok {
			// ... manejar el error ...
			return
		}

		// ... usar los claims (claims.Name, claims.Roles, etc.) ...
		w.Write([]byte("Acceso concedido al usuario: " + claims.Name))
	})

	mux := http.NewServeMux()
	mux.Handle("/api/protected", azureValidator.Middleware(myProtectedHandler))

	_ = http.ListenAndServe(":8080", mux)
}

```

### Opciones de Configuración
> Al crear un nuevo Validator, puedes pasar las siguientes opciones:
> 
> `WithAudiences([]string)`: 
> 
> Especifica una lista de audiences válidas. Requerido a menos que se deshabilite la validación.
>
> `WithoutAudienceValidation()`: 
> 
> Deshabilita la validación del claim de audiencia. No recomendado para producción.
>
> `WithLogger(*zap.Logger)`: 
> 
> Inyecta una instancia de zap.Logger. Si no se proporciona, se crea un logger de producción por defecto.