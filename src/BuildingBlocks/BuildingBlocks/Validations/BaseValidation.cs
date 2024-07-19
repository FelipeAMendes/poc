using BuildingBlocks.Validations.Interfaces;
using FluentValidation;
using FluentValidation.Results;
using System.ComponentModel.DataAnnotations.Schema;

namespace BuildingBlocks.Validations;

public abstract class BaseValidation<TValidation> where TValidation : IValidator, new()
{
    [NotMapped] public virtual IList<ValidationFailure> Errors => Validate()?.Errors!;

    public ValidationResult Validate()
    {
        var validation = new TValidation();
        var context = new ValidationContext<object>(this);
        var validationResult = validation.Validate(context);
        return validationResult;
    }
}

public abstract class BaseValidation : IBaseValidation
{
    private readonly List<ValidationFailure> _errors;

    protected BaseValidation()
    {
        _errors = [];
    }

    public void AddError(string propertyName, string errorMessage)
    {
        var validationFailure = new ValidationFailure(propertyName, errorMessage);

        _errors.Add(validationFailure);
    }

    public void AddError(string errorMessage)
    {
        AddError(null, errorMessage);
    }

    public void AddErrors(IList<ValidationFailure> errors)
    {
        if (errors is not null)
            _errors.AddRange(errors);
    }

    public IList<ValidationFailure> Errors => _errors;

    public bool IsValid => _errors.Count == 0;
}
