<?php

/**
 * @copyright Copyright (C) eZ Systems AS. All rights reserved.
 * @license For full copyright and license information view LICENSE file distributed with this source code.
 */
declare(strict_types=1);

namespace EzSystems\EzPlatformAdminUi\EventListener;

use DateTime;
use DateTimeInterface;
use eZ\Publish\API\Repository\UserService;
use eZ\Publish\Core\MVC\Symfony\Security\UserInterface;
use EzSystems\EzPlatformAdminUi\Notification\NotificationHandlerInterface;
use EzSystems\EzPlatformAdminUi\Specification\SiteAccess\IsAdmin;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Http\SecurityEvents;
use Symfony\Component\Security\Http\Event\InteractiveLoginEvent;
use Symfony\Component\Translation\TranslatorInterface;

final class CredentialsExpirationWarningListener implements EventSubscriberInterface
{
    /** @var \EzSystems\EzPlatformAdminUi\Notification\NotificationHandlerInterface */
    private $notificationHandler;

    /** @var \Symfony\Component\Translation\TranslatorInterface */
    private $translator;

    /** @var \Symfony\Component\Routing\Generator\UrlGeneratorInterface */
    private $urlGenerator;

    /** @var \eZ\Publish\API\Repository\UserService */
    private $userService;

    /** @var array */
    private $siteAccessGroups;

    public function __construct(
        NotificationHandlerInterface $notificationHandler,
        TranslatorInterface $translator,
        UrlGeneratorInterface $urlGenerator,
        UserService $userService,
        array $siteAccessGroups
    ) {
        $this->notificationHandler = $notificationHandler;
        $this->translator = $translator;
        $this->urlGenerator = $urlGenerator;
        $this->siteAccessGroups = $siteAccessGroups;
        $this->userService = $userService;
    }

    public function onAuthenticationSuccess(InteractiveLoginEvent $event): void
    {
        if (!$this->isAdminSiteAccess($event->getRequest())) {
            return;
        }

        $user = $event->getAuthenticationToken()->getUser();
        if (!($user instanceof UserInterface)) {
            return;
        }

        $apiUser = $user->getAPIUser();

        $passwordInfo = $this->userService->getPasswordInfo($apiUser);
        if ($passwordInfo->hasExpirationDate()) {
            $expirationWarningDate = $passwordInfo->getExpirationDate();
            if ($expirationWarningDate < new DateTime()) {
                $this->generateNotification($expirationWarningDate);
            }
        }
    }

    public static function getSubscribedEvents(): array
    {
        return [
            SecurityEvents::INTERACTIVE_LOGIN => ['onAuthenticationSuccess', 12],
        ];
    }

    private function generateNotification(DateTimeInterface $passwordExpiresAt): void
    {
        $passwordExpiresIn = (new DateTime())->diff($passwordExpiresAt);

        $this->notificationHandler->warning($this->translator->trans(
            'user_password_expire_warning',
            [
                'days' => $passwordExpiresIn->days,
                'url' => $this->urlGenerator->generate('ezplatform.user_profile.change_password'),
            ],
            'user_password_change'
        ));
    }

    private function isAdminSiteAccess(Request $request): bool
    {
        return (new IsAdmin($this->siteAccessGroups))->isSatisfiedBy($request->attributes->get('siteaccess'));
    }
}
