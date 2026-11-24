// Read-only Swagger UI for the committed schema (openapi/v1.json), served by
// deploy/nginx/admin-bff-docs.conf. Nothing is sent to the API from here: the
// real API needs HTTPS and a session cookie.
window.ui = SwaggerUIBundle({
  url: "/v1.json",
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
