<?php
declare(strict_types=1);

namespace wise\jwt\validator;

use wise\jwt\exception\JwtException;

/**
 * 声明校验器 — 责任链模式，可插拔的校验规则集合
 *
 * 支持自定义规则注册（静态注册 + 实例注入）：
 * Validator::registerRule(new CustomClaimRule());
 */
class Validator
{
    /** @var RuleInterface[] */
    protected array $rules = [];

    /** @var RuleInterface[] 全局注册的自定义规则（自动注入每个实例） */
    protected static array $registeredRules = [];

    public function __construct(protected int $leeway = 0) {}

    /**
     * 添加一条校验规则（实例级）
     */
    public function addRule(RuleInterface $rule): self
    {
        $this->rules[] = $rule;
        return $this;
    }

    /**
     * 移除一条校验规则（实例级）
     */
    public function removeRule(string $class): self
    {
        $this->rules = array_filter($this->rules, fn($rule) => !($rule instanceof $class));
        return $this;
    }

    /**
     * 全局注册自定义校验规则（自动注入所有新创建的 Validator 实例）
     *
     * 建议在 AppServiceProvider::boot() 中注册：
     * Validator::registerRule(new CustomRoleRule());
     */
    public static function registerRule(RuleInterface $rule): void
    {
        self::$registeredRules[] = $rule;
    }

    /**
     * 获取所有全局注册的自定义规则
     *
     * @return RuleInterface[]
     */
    public static function getRegisteredRules(): array
    {
        return self::$registeredRules;
    }

    /**
     * 清除所有全局注册的规则（测试用）
     */
    public static function clearRegisteredRules(): void
    {
        self::$registeredRules = [];
    }

    /**
     * 将全局注册的规则注入当前实例（由 JwtGuardManager 在构建 Validator 后调用）
     */
    public function applyRegisteredRules(): self
    {
        foreach (self::$registeredRules as $rule) {
            $this->rules[] = $rule;
        }
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
