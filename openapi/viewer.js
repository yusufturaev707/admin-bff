// Read-only Swagger UI for the committed schema (openapi/v1.json), served by
// deploy/nginx/admin-api.conf (part 3) on the same paths as the API itself
// (/api/v1/docs, /api/v1/openapi.json). Nothing is sent to the API from here:
// the real API needs HTTPS and a session cookie.
window.ui = SwaggerUIBundle({
  url: "/api/v1/openapi.json",
  dom_id: "#swagger-ui",
  deepLinking: true,
  displayOperationId: true,
  docExpansion: "none",
  defaultModelsExpandDepth: 0,
  filter: true,
  showExtensions: true,
  showCommonExtensions: true,
  supportedSubmitMethods: [],
  queryConfigEnabled: false,
});
