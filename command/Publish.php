<?php
declare(strict_types=1);

namespace wise\jwt\command;

use think\console\Command;
use think\console\Input;
use think\console\Output;
use think\console\input\Option;
use wise\jwt\trait\CommandTrait;

class Publish extends Command
{
    use CommandTrait;

    protected function configure()
    {
        $this->setName('wise:jwt:publish')
            ->addOption('force', 'f', Option::VALUE_NONE, '强制覆盖已存在的配置文件')
            ->setDescription('发布 wise-jwt 配置和迁移文件到项目')
            ->setHelp('发布 wise-jwt 配置和迁移文件到项目');
    }

    protected function getPackageConfigName(): string
    {
        return 'wise-jwt';
    }

    protected function execute(Input $input, Output $output)
    {
        $force = $input->getOption('force');

        $this->printBanner($output, 'wise-jwt');
        $this->publishConfig($output, $force);
        $this->publishMigrations($output);
        $this->printSuccessFooter($output, 'Wise JWT', false);

        return 0;
    }
}
