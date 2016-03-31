<?php
namespace common\models;

use Yii;
use yii\base\NotSupportedException;
use yii\behaviors\TimestampBehavior;
use yii\db\ActiveRecord;
use yii\Expression;
use yii\web\IdentityInterface;
use yii\helpers\Security;

/**
 * User model
 *
 * @property integer $id
 * @property string $username
 * @property string $password_hash
 * @property string $password_reset_token
 * @property string $email
 * @property string $auth_key
 * @property integer $status
 * @property integer $created_at
 * @property integer $updated_at
 * @property string $password write-only password
 */
class User extends ActiveRecord implements IdentityInterface
{
    const STATUS_ACTIVE = 1;

    /**
     * @inheritdoc
     * Este método indica la tabla al cual estaremos trabajando
     */
    public static function tableName()
    {
        return 'user';
    }

    /**
     * behaviors
     * Con este método identificamos el tipod e comportamiento indicandole la clase a usar, después definimos los eventos la cual cada uno
     * tiene sus propios atributos representados como campos en nuestra tabla; por último usamos la función now() ne mysql para la fecha actual.
     
    public function behaviors()
    {
        return [
            'timestamp' => [
                'class' => 'yii\behaviors\TimestampBehaviors',
                    'attributes' => [
                    ActiveRecord::EVENT_BEFORE_INSERT => ['created_at', 'updated_at'],
                    ActiveRecord::EVENT_BEFORE_UPDATE => ['updated_at'],
                    ],
                'value' => new Expression('NOW()'),
            ],
        ];
    }*/
    
    public function behaviors()
    {
        return [
            'timestamp' => [
                'class' => 'yii\behaviors\TimestampBehavior',
                'attributes' => [
                    ActiveRecord::EVENT_BEFORE_INSERT => ['created_at', 'updated_at'],
                    ActiveRecord::EVENT_BEFORE_UPDATE => ['updated_at'],
                ],
                'value' => new Expression('NOW()'),
            ],
        ];
    }

    /**
     * rules of validation
     * Se especifican las reglas de validaciones de cada uno de los atributos
     */
    public function rules()
    {
        return [
            ['status_id', 'default', 'value' => self::STATUS_ACTIVE],
            
            ['rol_id', 'default', 'value' => 1],
            
            ['type_user_id', 'default', 'value' => 1],
            
            ['username', 'filter', 'filter' => 'trim'],
            ['username', 'required'],
            ['username', 'unique'],
            ['username', 'string', 'min' => 2, 'max' => 255],
            
            ['email', 'filter', 'filter' => 'trim'],
            ['email', 'required'],
            ['email', 'email'],
            ['email', 'unique']
        ];
    }

    
    /**
     * Labels of the atributs of he model
     */
    
    public function attributeLabels() {
        return[
            /* others labels of atributs */
        ];
    }
    
    /**
     * @findIndentity
     */
    
    public static function findIdentity($id){
        return static::findOne(['Id' => $id, 'estatus_id' => self::STATUS_ACTIVE]);
    }
     
    
    /**
     * @inheritdoc
     */
   
    public static function findIdentityByAccessToken($token, $type = null) {
        throw new NotSupportedException('"findIdentityAccessToken" is not implemented.');
    }
    
    /**
     * Encuentra usuario por username
     * @param string $username
     * @return static|null
     */
    
    public static function findByUsername($username){
        return static::findOne(['username' => $username, 'status_id' => self::STATUS_ACTIVE]);
    }
    
    /**
     *Encuentra usuario por clave de restablecimiento de password
     * @param string $token clave de restablecimiento de password
     * @return static|null
     */
    
    public static function findByPasswordResetToken($token){
        if(!static::isPasswordResetTokenValid($token)){
            return null;
        }
        return static::findObne([
            'password_reset_token' => $token,
            'status_id' => self::STATUS_ACTIVE,
        ]);
    }
    
    /**
     * Determina si la clave de restablecimiento de password es valida
     * 
     * @param strin $token clave de restablecimiento de password
     * @retur boolean
     */
    
    public static function isPasswordResetTokenValid($token){
        if(empty($token)){
            return false;
        }
        $expire = Yii::$app->params['user.passwordResetTokenExpire'];
        $parts = explode('_',$token);
        $timestamp = (int) end($parts);
        return $timestamp + $expire >= time();
    }
    
    /**
     * @getId
     */
    
    public function getId() {
        return $this->getPrimaryKey();
    }
    
    /**
     * @getAutKey
     */
    
    public function getAuthKey() {
        return $this->auth_key;
    }
    
    /**
     * @validateAuthKey
     */
    
    public function validateAuthKey($authKey) {
        return $this->getAuthKey() === $authKey;
    }
    
    /**
     * Valida password
     * 
     * @param string $password password a validar
     * @return boolean si el password provista es válida par el usuario actual
     */
    
    public function validatePassword($password){
        return Yii::$app->security->validatePassword($password, $this->password-has);
    }
    
    /**
     * Genera has de psswor a partir de password y la establece en el modelo
     * 
     * @param string $password
     */
    
    public function setPassword($password){
        $this->password_hash = Yii::$app->security->generatePasswordHash($password);
    }
    
    /**
     * Genera clave de autentificación "recuerdame"
     */
    public function generateAuthkey(){
        $this->auth_key = Yii::$app->security->generateRandomString();
    }
    
    /**
     * Genera nueva clave de reestablecimiento de password
     */
    public function generatePasswordResetToken(){
        $this->password_reset_token = Yii::$app->security->generateRandomString().'_'.time();
    }
    
    /**
     * Remueve clave de reestablecimiento de password
     */
    
    public function removePasswordResetToken() {
        $this->password_reset_token = null;
    }
}