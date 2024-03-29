﻿using Indice.Psd2.Cryptography;
using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.SwaggerGen;

namespace Indice.Oba.Host.Swagger;

public class SchemaExamplesFilter : ISchemaFilter
{
    public void Apply(OpenApiSchema schema, SchemaFilterContext context) {
        if (context.Type == typeof(Psd2CertificateRequest)) {
            schema.Example = Psd2CertificateRequest.Example().ToOpenApiAny();
        }
    }
}
