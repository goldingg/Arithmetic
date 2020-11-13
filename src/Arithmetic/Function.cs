using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;

using Amazon.Lambda.Core;
using Amazon.Lambda.APIGatewayEvents;

using CVE.BasicLambda.Arithmetic;
using CVE.BasicLambda.Models;
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

            response.Headers = new Dictionary<string, string>();
            response.Headers.Add("content-type", "application/json");

            if (request.HttpMethod == "HEAD")
            {
                int page, pageSize;
                if (TryParseQueryString(request.QueryStringParameters, out page, out pageSize))
                    response.StatusCode = 200;
                else
                    response.StatusCode = 400;
            }
            else if (request.HttpMethod == "GET")
            {
                int page, pageSize;
                if (TryParseQueryString(request.QueryStringParameters, out page, out pageSize))
                {
                    IEnumerable<ArithmeticExpression> expressions;
                    if (pageSize <= 0)
                    {
                        expressions = GetExpressions(page);
                    }
                    else
                    {
                        expressions = GetExpressions(page, pageSize);
                    }
                    
                    response.StatusCode = 200;
                    response.Body = JsonSerializer.Serialize<IEnumerable<ArithmeticExpression>>(expressions,
                        new JsonSerializerOptions() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, WriteIndented = true });
                }
                else
                {
                    response.StatusCode = 400;
                    response.Body = $@"{{
                        ""error"": ""The query string arguments are invalid."",
                        ""parameters"": [
                            {{
                                ""hasDefaultValue"": false,
                                ""name"": ""page"",
                                ""required"": true,
                                ""type"": ""Int32"",
                                ""typeDescription"": ""Signed 32-bit whole number""
                            }},
                            {{
                                ""hasDefaultValue"": true,
                                ""defaultValue"": 25,
                                ""name"": ""page-size"",
                                ""required"": false,
                                ""type"": ""Int32"",
                                ""typeDescription"": ""Signed 32-bit whole number""
                            }}
                        ]
                    }}";
                }
            }
            else if(request.HttpMethod == "POST")
            {
                var expression = JsonSerializer.Deserialize<Expression>(request.Body,
                    new JsonSerializerOptions(){ PropertyNameCaseInsensitive = true });
                if (expression == null
                    || expression.Operator == null
                )
                {
                    response.Body = request.Body;
                    return response;
                }

                var expressionResult = ArithmeticExpressionHandler(expression);
                try
                {
                    SaveRequest(expression, expressionResult);
                    response.StatusCode = 200;
                }
                catch (System.Exception)
                {
                    response.StatusCode = 500;
                }

                response.Body = expressionResult;
            }
            else if (
                request.HttpMethod == "PUT"
                || request.HttpMethod == "PATCH"
                || request.HttpMethod == "DELETE"
                || request.HttpMethod == "OPTIONS"
            )
            {
                response.StatusCode = 405;
                response.Headers.Add("Allow", "HEAD, GET, POST");
                response.Body = $@"{{
                    ""error"": ""The HTTP method is not allowed on this resource."",
                    ""httpMethod"": ""{request.HttpMethod}"",
                    ""allowedHttpMethods"": [""HEAD"", ""GET"", ""POST""],
                    ""resourceRequested"": ""{request.Resource}""
                }}";
            }
            else
            {
                response.StatusCode = 400;
                response.Headers.Add("Allow", "HEAD, GET, POST");
                response.Body = $@"{{
                    ""error"": ""The server does not know the HTTP method that was used."",
                    ""httpMethod"": ""{request.HttpMethod}"",
                    ""allowedHttpMethods"": [""HEAD"", ""GET"", ""POST""]
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

        private IEnumerable<ArithmeticExpression> GetExpressions(int page, int pageSize = 25)
        {
            using var db = new ArithmeticContext();

            var query = db.ArithmeticExpression.AsQueryable();
            query = query.Skip(page * pageSize).Take(pageSize);

            return query.ToList();
        }

        private void SaveRequest(Expression expression, string result)
        {
            Success success;
            try
            {
                success = JsonSerializer.Deserialize<Success>(result, new JsonSerializerOptions(){ PropertyNameCaseInsensitive = true });
            }
            catch (System.Exception)
            {
                return;
            }
            
            char? selectedOperator;
            switch (expression.Operator.ToUpper())
            {
                case "ADD":
                    selectedOperator = '+';
                    break;
                case "SUBTRACT":
                    selectedOperator = '-';
                    break;
                case "MULTIPLY":
                    selectedOperator = '*';
                    break;
                case "DIVIDE":
                    selectedOperator = '/';
                    break;
                default:
                    selectedOperator = null;
                    break;
            }

            var arithmeticExpression = new ArithmeticExpression()
            {
                LeftOperand = expression.LeftOperand,
                RightOperand = expression.RightOperand,
                Operator = selectedOperator,
                Result = success.Result
            };
            using var db = new ArithmeticContext();
            db.ArithmeticExpression.Add(arithmeticExpression);
            db.SaveChanges();
        }

        private bool TryParseQueryString(IDictionary<string, string> queryArgs, out int page, out int pageSize)
        {
                var success = false;
                string pageArg, pageSizeArg;

                page = -1; pageSize = -1;

                if (queryArgs == null)
                    return success;
                
                if (queryArgs.TryGetValue("page", out pageArg) && queryArgs.TryGetValue("page-size", out pageSizeArg))
                {
                    try { page = Int32.Parse(pageArg); }
                    catch (System.Exception) { return success; }

                    try { pageSize = Int32.Parse(pageSizeArg); }
                    catch (System.Exception) { return success; }

                    if (page-- > 0 && pageSize >= 10 && pageSize <= 100)
                        success = true;
                }
                else if (queryArgs.TryGetValue("page", out pageArg))
                {
                    try { page = Int32.Parse(pageArg); }
                    catch (System.Exception) { return success; }

                    if (page-- > 0)
                        success = true;
                }

                return success;
        }
    }
}
