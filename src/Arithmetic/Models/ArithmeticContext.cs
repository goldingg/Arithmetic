using System;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;

namespace CVE.BasicLambda.Models
{
    public partial class ArithmeticContext : DbContext
    {
        public ArithmeticContext()
        {
        }

        public ArithmeticContext(DbContextOptions<ArithmeticContext> options)
            : base(options)
        {
        }

        public virtual DbSet<ArithmeticExpression> ArithmeticExpression { get; set; }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            if (!optionsBuilder.IsConfigured)
            {
                optionsBuilder.UseNpgsql(System.Environment.GetEnvironmentVariable("DB_CONNECTION_STRING"));
            }
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.HasPostgresExtension("pgcrypto");

            modelBuilder.Entity<ArithmeticExpression>(entity =>
            {
                entity.ToTable("arithmetic_expression");

                entity.Property(e => e.Id)
                    .HasColumnName("id")
                    .UseIdentityAlwaysColumn();

                entity.Property(e => e.CreatedAt)
                    .HasColumnName("created_at")
                    .HasColumnType("timestamp with time zone")
                    .HasDefaultValueSql("clock_timestamp()");

                entity.Property(e => e.LeftOperand).HasColumnName("left_operand");

                entity.Property(e => e.ModifiedAt)
                    .HasColumnName("modified_at")
                    .HasColumnType("timestamp with time zone")
                    .HasDefaultValueSql("clock_timestamp()");

                entity.Property(e => e.Operator).HasColumnName("operator");

                entity.Property(e => e.Result).HasColumnName("result");

                entity.Property(e => e.RightOperand).HasColumnName("right_operand");

                entity.Property(e => e.Uuid)
                    .HasColumnName("uuid")
                    .HasDefaultValueSql("gen_random_uuid()");
            });

            OnModelCreatingPartial(modelBuilder);
        }

        partial void OnModelCreatingPartial(ModelBuilder modelBuilder);
    }
}
