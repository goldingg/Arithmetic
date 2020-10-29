namespace CVE.BasicLambda.Arithmetic
{
    public class Expression
    {
        public double LeftOperand { get; set; }
        public double RightOperand { get; set; }
        public string Operator { get; set; }

        public double Evaluate()
        {
            return Operator.ToUpper() switch
            {
                "ADD" => LeftOperand + RightOperand,
                "SUBTRACT" => LeftOperand - RightOperand,
                "MULTIPLY" => LeftOperand * RightOperand,
                "DIVIDE" => LeftOperand / RightOperand,
                _ => -1,
            };
        }
    }
}
