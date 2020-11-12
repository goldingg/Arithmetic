using System;
using System.Collections.Generic;

namespace CVE.BasicLambda.Models
{
    public partial class ArithmeticExpression
    {
        public int Id { get; set; }
        public Guid Uuid { get; set; }
        public DateTimeOffset CreatedAt { get; set; }
        public DateTimeOffset ModifiedAt { get; set; }
        public double? LeftOperand { get; set; }
        public char? Operator { get; set; }
        public double? RightOperand { get; set; }
        public double? Result { get; set; }
    }
}
