<?php
namespace Piwik\Plugins\OneLogin;

use Exception;
use Piwik\Container\StaticContainer;
use Piwik\Plugin\Manager;
use Piwik\Plugins\Login\Login;

class OneLogin extends \Piwik\Plugin
{
    public function registerEvents()
    {
        return array(
            'Request.initAuthenticationObject' => 'initAuthenticationObject',
            'User.isNotAuthorized'             => 'noAccess',
            'API.Request.authenticate'         => 'ApiRequestAuthenticate',
        );
    }

    /**
     * Deactivate default Login module, as both cannot be activated together
     */
    public function activate()
    {
        if (Manager::getInstance()->isPluginActivated("Login") == true) {
            Manager::getInstance()->deactivatePlugin("Login");
        }
    }

    /**
     * Activate default Login module, as one of them is needed to access Piwik
     */
    public function deactivate()
    {
        if (Manager::getInstance()->isPluginActivated("Login") == false) {
            Manager::getInstance()->activatePlugin("Login");
        }
    }

    public function initAuthenticationObject($activateCookieAuth = false)
    {
        $auth = new Auth();
        StaticContainer::getContainer()->set('Piwik\Auth', $auth);

        $login = new Login();
        return $login->initAuthenticationFromCookie($auth, $activateCookieAuth);
    }

    public function ApiRequestAuthenticate($tokenAuth)
    {
        $login = new Login();
        return $login->ApiRequestAuthenticate($tokenAuth);
    }

    public function noAccess(Exception $exception)
    {
        $login = new Login();
        return $login->noAccess($exception);
    }
}
