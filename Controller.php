<?php
namespace Piwik\Plugins\OneLogin;

use Piwik\Config;
use Piwik\View;
use Piwik\Url;

class Controller extends \Piwik\Plugins\Login\Controller
{
    function callback()
    {
        $auth = (new Auth());
        $result = $auth->authenticate();
        if ($result->wasAuthenticationSuccessful()) {
            $si = new \Piwik\Plugins\Login\SessionInitializer();
            $si->initSession($auth, true);
            $urlToRedirect = Url::getCurrentUrlWithoutQueryString();
            Url::redirectToUrl($urlToRedirect);
            exit;
        }
        exit('invalid authentication');
    }

    public function login($messageNoAccess = NULL, $infoMessage = false)
    {
        $config = Config::getInstance()->OneLogin;
        header('Location: https://'.$config['subdomain'].'.onelogin.com/launch/'.$config['app_id']);
        exit;
    }
}
