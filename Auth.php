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
        $login = $this->doOneLogin();
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

    private function createUser($login, $password, $email, $alias=false) {
        $self = $this;
        return Access::doAsSuperUser(function () use ($self, $login, $password, $email, $alias) {
            $api = $self->usersManagerAPI;
            return $api->addUser($login, $password, $email, $alias);
        });
    }

    protected function doOneLogin() {
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

        $login = $this->getLoginByEmail($email);
        if (empty($login) && isset($config['add_users']) && $config['add_users'] > 0) {
            $newuser = preg_replace("/[^a-zA-Z0-9]+/", "", explode('@', $email)[0]);
            $newpass = md5(openssl_random_pseudo_bytes(64));
            $r = $this->createUser($newuser, $newpass, $email, "$firstname $lastname");
            $login = $this->getLoginByEmail($email);
        }
        if (empty($login)) {
            exit("Hi $firstname $lastname ($email). No account exists for you yet. Please contact: ".$config['admin_contact']);
        }
        return $login;
    }

    private function getLoginByEmail($email) {
        $login = '';
        $user = $this->getUserByEmail($email);
        if (is_array($user)) {
            $login = $user['login'];
        }
        return $login;        
    }

    private function getUserByEmail($email) {
        $usersManager = $this->usersManagerAPI;
        return Access::doAsSuperUser(function () use ($email, $usersManager) {
            $user = null;
            if ($usersManager->userEmailExists($email)) {
                $user = $usersManager->getUserByEmail($email);
            }
            return $user;
        });
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

