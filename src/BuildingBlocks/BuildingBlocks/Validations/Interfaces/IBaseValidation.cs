using FluentValidation.Results;

namespace BuildingBlocks.Validations.Interfaces;

public interface IBaseValidation
{
    IList<ValidationFailure> Errors { get; }
}
