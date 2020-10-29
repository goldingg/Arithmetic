using System;
using System.Text.Json;

using Amazon.Lambda.Core;

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
            string resultJsonPayload;
            JsonSerializerOptions serializerOptions = new JsonSerializerOptions() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, WriteIndented = true };

            try
            {
                var success = new Success() { Result = input.Evaluate() };
                resultJsonPayload = JsonSerializer.Serialize<Success>(success, serializerOptions);
            }
            catch (Exception exception)
            {
                Failure failure = new Failure()
                {
                    Error = "The server encountered an error.",
                    ErrorType = exception.GetType().ToString(),
                    Message = exception.Message
                };

                resultJsonPayload = JsonSerializer.Serialize<Failure>(failure, serializerOptions);
            }

            return resultJsonPayload ?? "\"Something went wrong.\"";
        }
    }
}
