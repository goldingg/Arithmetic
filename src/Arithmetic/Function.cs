using System;
using System.Text.Json;

using Amazon.Lambda.Core;
using Amazon.Lambda.APIGatewayEvents;

using CVE.BasicLambda.Arithmetic;
using CVE.BasicLambda.Responses;

// Assembly attribute to enable the Lambda function's JSON input to be converted into a .NET class.
[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer))]

namespace CVE.BasicLambda
{
    public class Function
    {
        
        /// <summary>
        /// A simple function that takes a string and does a ToUpper
        /// </summary>
        /// <param name="input"></param>
        /// <param name="context"></param>
        /// <returns></returns>
        public string FunctionHandler(Expression input, ILambdaContext context)
        {
            return ArithmeticExpressionHandler(input);
        }

        /// <summary>
        /// A function that handles a basic API Gateway REST event.
        /// </summary>
        /// <param name="request"></param>
        /// <param name="context"></param>
        /// <returns></returns>
        public APIGatewayProxyResponse ApiGatewayRestHandler(APIGatewayProxyRequest request, ILambdaContext context)
        {
            var response = new APIGatewayProxyResponse();

            response.Headers = new System.Collections.Generic.Dictionary<string, string>();
            response.Headers.Add("content-type", "application/json");

            if (request.HttpMethod == "POST")
            {
                response.StatusCode = 200;

                var expression = JsonSerializer.Deserialize<Expression>(request.Body,
                    new JsonSerializerOptions(){ PropertyNameCaseInsensitive = true });
                if (expression == null
                    || expression.Operator == null
                )
                {
                    response.Body = request.Body;
                    return response;
                }

                response.Body = ArithmeticExpressionHandler(expression);
            }
            else if (request.HttpMethod == "HEAD"
                || request.HttpMethod == "GET"
                || request.HttpMethod == "PUT"
                || request.HttpMethod == "PATCH"
                || request.HttpMethod == "DELETE"
                || request.HttpMethod == "OPTIONS"
            )
            {
                response.StatusCode = 405;
                response.Headers.Add("Allow", "POST");
                response.Body = $@"{{
                    ""error"": ""The HTTP method is not allowed on this resource."",
                    ""httpMethod"": ""{request.HttpMethod}"",
                    ""allowedHttpMethods"": [""POST""],
                    ""resourceRequested"": ""{request.Resource}""
                }}";
            }
            else
            {
                response.StatusCode = 400;
                response.Headers.Add("Allow", "POST");
                response.Body = $@"{{
                    ""error"": ""The server does not know the HTTP method that was used."",
                    ""httpMethod"": ""{request.HttpMethod}"",
                    ""allowedHttpMethods"": [""POST""]
                }}";
            }

            return response;
        }

        private string ArithmeticExpressionHandler(Expression expression)
        {
            string resultJsonPayload;
            JsonSerializerOptions serializerOptions = new JsonSerializerOptions() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, WriteIndented = true };

            try
            {
                var success = new Success() { Result = expression.Evaluate() };
                resultJsonPayload = JsonSerializer.Serialize<Success>(success, serializerOptions);
            }
            catch (Exception exception)
            {
                Failure failure = new Failure()
                {
                    Error = "The server encountered an error.",
                    ErrorType = exception.GetType().ToString(),
                    Message = exception.Message,
                    StackTrace = exception.StackTrace
                };

                resultJsonPayload = JsonSerializer.Serialize<Failure>(failure, serializerOptions);
            }

            return resultJsonPayload ?? "\"Something went wrong.\"";
        }
    }
}
