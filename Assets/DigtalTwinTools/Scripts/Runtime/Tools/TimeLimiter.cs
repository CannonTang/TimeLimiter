using System.Collections;
using System.Collections.Generic;
using UnityEngine;
using System;
using Newtonsoft.Json;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using UnityEngine.Events; 

namespace DigtalTwinTools.Runtime
{ 
    public class TimeLimiter : MonoBehaviour
    {
        [Header("离线时间限制器，时间缓存在PlayerPrefs与StreamingAssets中，基于AES加密算法实现")]
        [Header("必须配合 Obfuscator Pro 代码混淆插件使用（导入即可）")]
        [Header("否则此组件内部的加解密算法、Inspector面板中的密钥等，理论上都是可以被解包反编译出来的")]
        #region Elements

        [SerializeField]
        private TimeLimiterData timeLimiterData = new TimeLimiterData();

        public string timeLimiterJsonPath
        {
            get { return Application.streamingAssetsPath + "/UnityCrashLog.crash"; }
        }

        private float calTime=0;

        [Range(30,120)]
        /// <summary>
        /// 检查频率（秒）
        /// </summary>
        public float CheckRate = 60;
          
        [Header("过期、或者同时修改两处缓存导致的报错触发时，会触发的事件")]
        public UnityEvent outDateEvent;

        #endregion

        #region Unity Life Cycle

        private void Start()
        {
            CheckState();
        }

        private void Update()
        {
            calTime += Time.unscaledDeltaTime;
            if (calTime > CheckRate)
            {
                calTime = 0;
                CheckState();
            }
        }

        #endregion

        #region Logic

        /// <summary>
        /// 初始化函数，只在Unity编辑器中初始化执行，过期时间记得手动修改
        /// </summary>
        [ContextMenu("初始化")]
        public void Initialize()
        {
#if UNITY_EDITOR

            DateTime now = DateTime.Now;
            timeLimiterData.InitializeTime = now.ToString();
            timeLimiterData.CurrentTime = now.ToString();
             
            if (DateTime.TryParse(timeLimiterData.OutdateTime, out DateTime outdateTime))
            {
                TimeSpan difference = outdateTime - now;
                timeLimiterData.remainTime = difference.TotalSeconds.ToString();

                if (difference.TotalSeconds > 0)
                {
                    SaveTimeLimiterData();

                    Debug.Log("更新 初始化时间 和最近一次打开的时间");
                    Debug.Log("剩余时间已设置为 " + timeLimiterData.remainTime + " 秒");
                }
                else
                {
                    Debug.LogError("过期时间小于初始化时间，这是无效的");
                }

            }
            else
            {
                Debug.LogError("过期时间填写无效，请手动修改成正确的值，然后再执行初始化");
            }
#endif
        }

        private void SaveTimeLimiterData()
        {
#if UNITY_EDITOR
            Debug.Log("到了这一步，说明当前系统通过了时间检测，尚未过期");
#else
            Debug.Log("Registered");
#endif

            string timeLimiterDataStr = JsonConvert.SerializeObject(timeLimiterData);

            string timeLimiterDataStr_Code = Encode(timeLimiterDataStr);//加密

            if (!Directory.Exists(Application.streamingAssetsPath))
                Directory.CreateDirectory(Application.streamingAssetsPath);

            if (!File.Exists(timeLimiterJsonPath))
                File.Create(timeLimiterJsonPath).Dispose();

            File.WriteAllText(timeLimiterJsonPath, timeLimiterDataStr_Code);

            PlayerPrefs.SetString("RegisterKey", timeLimiterDataStr_Code);

            PlayerPrefs.Save();

        }

        // 检查的思路，首先检查注册表的时间，判断当前时间是否正常（基于上次存储的数据，判断用户是否修改了本地系统时间，如果没有修改，那么是不是在有效范围内未过期）
        //优先获取StreamingAssets中的数据，如果失败，则读取注册表内的数据（优先级低），进行过期检测
        //如果上述检测不通过，则执行OutdateEvent方法，否则表示通过检测，不执行OutdateEvent。
        //同样需要考虑加解密错误的情况（文件被修改），采取Try Catch的形式，如果报错，一样执行OutdateEvent
        // 检查完毕后，如果没有修改，则更新并保存次此时间数据，如果检测到修改了，则不保存
        private void CheckState()
        {
            try
            {
                string encryptedDataStr = string.Empty;

                try
                {
                    // 从文件中读取加密的时间数据
                    encryptedDataStr = File.ReadAllText(timeLimiterJsonPath);

                }
                catch
                {

                    Debug.LogError("time cache file read failed");

                    // PlayerPrefs中的数据
                    string prefsDataStr = PlayerPrefs.GetString("RegisterKey");

                    try
                    {
                        // 尝试解密PlayerPrefs中的数据，如果成功则使用这些数据
                        Decode(prefsDataStr);
                        encryptedDataStr = prefsDataStr;
                    }
                    catch
                    {

#if UNITY_EDITOR
                        Debug.LogError("两处缓存同时读取失败 , 误操作的可能性极低，执行outdate事件 ");
#else
                        Debug.LogError("RegisterKey read failed too");
#endif
                        OutdateEvent();
                        return;
                    }

                }

                // 解密数据
                string decryptedDataStr = Decode(encryptedDataStr);

                // 解析数据
                TimeLimiterData data = JsonConvert.DeserializeObject<TimeLimiterData>(decryptedDataStr);

                // 验证数据
                DateTime initializeTime = DateTime.Parse(data.InitializeTime);
                DateTime outdateTime = DateTime.Parse(data.OutdateTime);
                DateTime currentTime = DateTime.Parse(data.CurrentTime);
                DateTime now = DateTime.Now;

                // 检查系统时间是否被修改
                if (now < currentTime || now < initializeTime)
                {
                    OutdateEvent();
                    return;
                }

                // 检查是否超过使用期限
                if (now > outdateTime)
                {
                    OutdateEvent();
                    return;
                }

                // 检查剩余可用时间是否已经用完
                double remainTime = double.Parse(data.remainTime);
                double elapsedTime = (now - currentTime).TotalSeconds;
                if (elapsedTime > remainTime)
                {
                    OutdateEvent();
                    return;
                }

                // 如果所有检查都通过，那么使用当前时间更新上次打开时间，更新剩余可用时间，并保存数据
                data.CurrentTime = now.ToString();
                data.remainTime = (remainTime - elapsedTime).ToString();
                SaveTimeLimiterData();
            }
            catch (Exception ex)
            {
                // 如果处理过程中有错误（如解密错误），则视为过期
                Debug.LogError(ex.ToString());
                OutdateEvent();
            }
        }

        private void OutdateEvent()
        {
            outDateEvent?.Invoke();
            Debug.LogError("OutdateEvent was triggered");
        }

        [ContextMenu("打印解密的结果")]
        public void TryDecode()
        {
            Decode(File.ReadAllText(timeLimiterJsonPath));
        }

        /// <summary>
        /// 解密
        /// </summary> 
        public string Decode(string timeLimiterDataStr_Code)
        {
            string timeLimiterDataStr = Decrypt(timeLimiterDataStr_Code);

            //Debug.Log(timeLimiterDataStr);

            return timeLimiterDataStr;
        }

        /// <summary>
        /// 加密
        /// </summary> 
        public string Encode(string timeLimiterDataStr)
        {
            string timeLimiterDataStr_Code = Encrypt(timeLimiterDataStr);

            return timeLimiterDataStr_Code;
        }

#endregion

        #region AES 加密算法

        [Header("baseKey 和 baseIv 用于生成真正的 key 和 iv，建议使用英文和数字组合")]
        [Header("每个需要加密的项目都建议使用不同的key和iv，并重点保存以免丢失、泄密")]
        public string baseKey ="youhavetochangethisdefaultkey";
        public string baseIv= "youhavetochangethisdefaultiv";

        /// <summary>
        /// 实现一个固定的转换方法，基于 baseKey 转成 key，baseIv 转成 iv
        /// </summary>
        private void ConvertKeyAndIV()
        {
            using (SHA256 sha256Hash = SHA256.Create())
            {
                byte[] bytesKey = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(baseKey));
                byte[] bytesIv = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(baseIv));

                Array.Copy(bytesKey, 0, key, 0, key.Length);

                Array.Copy(bytesIv, 0, iv, 0, iv.Length);
            }
        }

        private byte[] key = new byte[32]; // 256 bits key
        private  byte[] iv = new byte[16]; // 128 bits IV

        private string Encrypt(string plainText)
        {
            ConvertKeyAndIV();

            byte[] encrypted;

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            return Convert.ToBase64String(encrypted);
        }

        private string Decrypt(string cipherText)
        {
            ConvertKeyAndIV();

            string plaintext = null;

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msDecrypt = new MemoryStream(Convert.FromBase64String(cipherText)))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }

        #endregion

    }

    /// <summary>
    /// 注：作为PlayerPrefs存储时，可存储最大1MB大小的数据
    /// </summary>
    [System.Serializable]
    public class TimeLimiterData
    {
        /// <summary>
        /// 初始化时间-----这是一个锚点，记录一个绝对准确的、真实的、不会倒退的时间，但也因此，除非使用Initialize函数，它会无法更新，始终停留在一个相对落后的阶段
        /// </summary>
        public string InitializeTime;

        /// <summary>
        /// 过期时间------手动修改
        /// </summary>
        public string OutdateTime;

        /// <summary>
        /// 最新一次打开的时间------不一定准确，因为客户的时间可能会被离线手动修改
        /// </summary>
        public string CurrentTime;

        /// <summary>
        /// 剩余可用时间（秒），用于辅助校验，
        /// 因为使用者仍然有可能通过每次往前调整一点点时间，来达到持续使用的效果（虽然繁琐但是可行），所以这里是必要的
        /// 每次Check时只会减少，而不是重新计算
        /// </summary>
        public string remainTime;
    }
     
}
