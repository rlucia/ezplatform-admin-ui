<?php

/**
 * @copyright Copyright (C) eZ Systems AS. All rights reserved.
 * @license For full copyright and license information view LICENSE file distributed with this source code.
 */
namespace EzSystems\EzPlatformAdminUi\Behat\BusinessContext;

use EzSystems\BehatBundle\Helper\ArgumentParser;
use EzSystems\EzPlatformAdminUi\Behat\Helper\EzEnvironmentConstants;
use EzSystems\EzPlatformAdminUi\Behat\PageElement\ElementFactory;
use EzSystems\EzPlatformAdminUi\Behat\PageElement\UniversalDiscoveryWidget;

class UDWContext extends BusinessContext
{
    private $argumentParser;

    /**
     * @injectService $argumentParser @EzSystems\BehatBundle\Helper\ArgumentParser
     */
    public function __construct(ArgumentParser $argumentParser)
    {
        $this->argumentParser = $argumentParser;
    }

    /**
     * @When I select content :pathToContent through UDW
     */
    public function iSelectContent(string $pathToContent): void
    {
        $udw = ElementFactory::createElement($this->utilityContext, UniversalDiscoveryWidget::ELEMENT_NAME);
        $udw->verifyVisibility();
        $pathToContent = $this->argumentParser->replaceRootKeyword($pathToContent);
        $udw->selectContent($pathToContent);
    }

    /**
     * @When I select content root node through UDW
     */
    public function iSelectRootNodeContent(): void
    {
        $this->iSelectContent(EzEnvironmentConstants::get('ROOT_CONTENT_NAME'));
    }

    /** @When I close the UDW window */
    public function iCloseUDW(): void
    {
        ElementFactory::createElement($this->utilityContext, UniversalDiscoveryWidget::ELEMENT_NAME)->cancel();
    }

    /** @When I confirm the selection in UDW */
    public function iConfirmSelection(): void
    {
        ElementFactory::createElement($this->utilityContext, UniversalDiscoveryWidget::ELEMENT_NAME)->confirm();
    }
}
