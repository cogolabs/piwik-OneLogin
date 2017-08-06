<?php
namespace Piwik\Plugins\OneLogin;

use Piwik\Access;
use Piwik\AuthResult;
use Piwik\Config;
use Piwik\Plugins\UsersManager\Model;
use Piwik\Plugins\UsersManager\API as UsersManagerAPI;

class Auth implements \Piwik\Auth
{
    /**
     * @var Model
     */
    private $userModel;
    private $usersManagerAPI;

    /**
     * @var Auth
     */
    private $fallbackAuth;

    /**
     * Constructor.
     *
     * @param Model|null $userModel
     */
    public function __construct(Model $userModel = null)
    {
        if ($userModel === null) {
            $userModel = new Model();
        }

        $this->userModel = $userModel;
        $this->usersManagerAPI = UsersManagerAPI::getInstance();
        $this->fallbackAuth = new \Piwik\Plugins\Login\Auth();
    }

    /**
     * Authentication module's name
     *
     * @return string
     */
    public function getName()
    {
        return 'OneLogin';
    }

    /**
     * Authenticates user
     *
     * @return \Piwik\AuthResult
     */
    public function authenticate()
    {
        $login = $this->getOneLogin();
        if (!empty($login)) {
            $user = $this->userModel->getUser($login);

            if(empty($user)) {
                return new AuthResult(AuthResult::FAILURE, $login, null);
            }

            $code = !empty($user['superuser_access']) ? AuthResult::SUCCESS_SUPERUSER_AUTH_CODE : AuthResult::SUCCESS;
            return new AuthResult($code, $login, $user['token_auth']);
        }
        return $this->fallbackAuth->authenticate();
    }

    protected function getOneLogin()
    {
        if (!isset($_GET['email']) || !isset($_GET['timestamp']) || !isset($_GET['signature'])) {
            return false;
        }
        if ($_GET['timestamp'] < time()-600) {
            exit('invalid timestamp');
        }

        $config = Config::getInstance()->OneLogin;
        $login = false;
        $secret = $config['security_token'];
        $firstname = '';
        if (isset($_GET['firstname'])) { $firstname = $_GET['firstname']; }
        if (isset($_GET['?firstname'])) { $firstname = $_GET['?firstname']; }
        $lastname = $_GET['lastname'];
        $email = $_GET['email'];
        $timestamp = $_GET['timestamp'];
        $x = sha1("$firstname$lastname$email$timestamp$secret");
        if ($x != $_GET['signature']) {
            exit('invalid signature');
        }

        $usersManager = $this->usersManagerAPI;
        $user = Access::doAsSuperUser(function () use ($email, $usersManager) {
            $user = null;
            if ($usersManager->userEmailExists($email)) {
                $user = $usersManager->getUserByEmail($email);
            }
            return $user;
        });
        if (is_array($user)) {
            $login = $user['login'];
        }
        if (empty($login)) {
            exit("Hi $firstname $lastname ($email). For access setup, please contact: ".$config['access_contact']);
        }
        return $login;
    }

    public function setTokenAuth($token_auth)
    {
        $this->fallbackAuth->setTokenAuth($token_auth);
    }

    public function getLogin()
    {
        $this->fallbackAuth->getLogin();
    }

    public function getTokenAuthSecret()
    {
        return $this->fallbackAuth->getTokenAuthSecret();
    }

    public function setLogin($login)
    {
        $this->fallbackAuth->setLogin($login);
    }

    public function setPassword($password)
    {
        $this->fallbackAuth->setPassword($password);
    }

    public function setPasswordHash($passwordHash)
    {
        $this->fallbackAuth->setPasswordHash($passwordHash);
    }
}

