<?php
declare(strict_types=1);

namespace wise\jwt\validator;

use wise\jwt\exception\JwtException;

/**
 * 声明校验器 — 责任链模式，可插拔的校验规则集合
 */
class Validator
{
    /** @var RuleInterface[] */
    protected array $rules = [];

    public function __construct(protected int $leeway = 0) {}

    public function addRule(RuleInterface $rule): self
    {
        $this->rules[] = $rule;
        return $this;
    }

    public function removeRule(string $class): self
    {
        $this->rules = array_filter($this->rules, fn($rule) => !($rule instanceof $class));
        return $this;
    }

    /**
     * @throws JwtException
     */
    public function validate(array $payload): void
    {
        foreach ($this->rules as $rule) {
            $rule->validate($payload);
        }
    }

    public function getLeeway(): int
    {
        return $this->leeway;
    }
}
