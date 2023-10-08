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
        [Header("����ʱ����������ʱ�仺����PlayerPrefs��StreamingAssets�У�����AES�����㷨ʵ��")]
        [Header("������� Obfuscator Pro ����������ʹ�ã����뼴�ɣ�")]
        [Header("���������ڲ��ļӽ����㷨��Inspector����е���Կ�ȣ������϶��ǿ��Ա���������������")]
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
        /// ���Ƶ�ʣ��룩
        /// </summary>
        public float CheckRate = 60;
          
        [Header("���ڡ�����ͬʱ�޸��������浼�µı�����ʱ���ᴥ�����¼�")]
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
        /// ��ʼ��������ֻ��Unity�༭���г�ʼ��ִ�У�����ʱ��ǵ��ֶ��޸�
        /// </summary>
        [ContextMenu("��ʼ��")]
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

                    Debug.Log("���� ��ʼ��ʱ�� �����һ�δ򿪵�ʱ��");
                    Debug.Log("ʣ��ʱ��������Ϊ " + timeLimiterData.remainTime + " ��");
                }
                else
                {
                    Debug.LogError("����ʱ��С�ڳ�ʼ��ʱ�䣬������Ч��");
                }

            }
            else
            {
                Debug.LogError("����ʱ����д��Ч�����ֶ��޸ĳ���ȷ��ֵ��Ȼ����ִ�г�ʼ��");
            }
#endif
        }

        private void SaveTimeLimiterData()
        {
#if UNITY_EDITOR
            Debug.Log("������һ����˵����ǰϵͳͨ����ʱ���⣬��δ����");
#else
            Debug.Log("Registered");
#endif

            string timeLimiterDataStr = JsonConvert.SerializeObject(timeLimiterData);

            string timeLimiterDataStr_Code = Encode(timeLimiterDataStr);//����

            if (!Directory.Exists(Application.streamingAssetsPath))
                Directory.CreateDirectory(Application.streamingAssetsPath);

            if (!File.Exists(timeLimiterJsonPath))
                File.Create(timeLimiterJsonPath).Dispose();

            File.WriteAllText(timeLimiterJsonPath, timeLimiterDataStr_Code);

            PlayerPrefs.SetString("RegisterKey", timeLimiterDataStr_Code);

            PlayerPrefs.Save();

        }

        // ����˼·�����ȼ��ע����ʱ�䣬�жϵ�ǰʱ���Ƿ������������ϴδ洢�����ݣ��ж��û��Ƿ��޸��˱���ϵͳʱ�䣬���û���޸ģ���ô�ǲ�������Ч��Χ��δ���ڣ�
        //���Ȼ�ȡStreamingAssets�е����ݣ����ʧ�ܣ����ȡע����ڵ����ݣ����ȼ��ͣ������й��ڼ��
        //���������ⲻͨ������ִ��OutdateEvent�����������ʾͨ����⣬��ִ��OutdateEvent��
        //ͬ����Ҫ���Ǽӽ��ܴ����������ļ����޸ģ�����ȡTry Catch����ʽ���������һ��ִ��OutdateEvent
        // �����Ϻ����û���޸ģ�����²�����δ�ʱ�����ݣ������⵽�޸��ˣ��򲻱���
        private void CheckState()
        {
            try
            {
                string encryptedDataStr = string.Empty;

                try
                {
                    // ���ļ��ж�ȡ���ܵ�ʱ������
                    encryptedDataStr = File.ReadAllText(timeLimiterJsonPath);

                }
                catch
                {

                    Debug.LogError("time cache file read failed");

                    // PlayerPrefs�е�����
                    string prefsDataStr = PlayerPrefs.GetString("RegisterKey");

                    try
                    {
                        // ���Խ���PlayerPrefs�е����ݣ�����ɹ���ʹ����Щ����
                        Decode(prefsDataStr);
                        encryptedDataStr = prefsDataStr;
                    }
                    catch
                    {

#if UNITY_EDITOR
                        Debug.LogError("��������ͬʱ��ȡʧ�� , ������Ŀ����Լ��ͣ�ִ��outdate�¼� ");
#else
                        Debug.LogError("RegisterKey read failed too");
#endif
                        OutdateEvent();
                        return;
                    }

                }

                // ��������
                string decryptedDataStr = Decode(encryptedDataStr);

                // ��������
                TimeLimiterData data = JsonConvert.DeserializeObject<TimeLimiterData>(decryptedDataStr);

                // ��֤����
                DateTime initializeTime = DateTime.Parse(data.InitializeTime);
                DateTime outdateTime = DateTime.Parse(data.OutdateTime);
                DateTime currentTime = DateTime.Parse(data.CurrentTime);
                DateTime now = DateTime.Now;

                // ���ϵͳʱ���Ƿ��޸�
                if (now < currentTime || now < initializeTime)
                {
                    OutdateEvent();
                    return;
                }

                // ����Ƿ񳬹�ʹ������
                if (now > outdateTime)
                {
                    OutdateEvent();
                    return;
                }

                // ���ʣ�����ʱ���Ƿ��Ѿ�����
                double remainTime = double.Parse(data.remainTime);
                double elapsedTime = (now - currentTime).TotalSeconds;
                if (elapsedTime > remainTime)
                {
                    OutdateEvent();
                    return;
                }

                // ������м�鶼ͨ������ôʹ�õ�ǰʱ������ϴδ�ʱ�䣬����ʣ�����ʱ�䣬����������
                data.CurrentTime = now.ToString();
                data.remainTime = (remainTime - elapsedTime).ToString();
                SaveTimeLimiterData();
            }
            catch (Exception ex)
            {
                // �������������д�������ܴ��󣩣�����Ϊ����
                Debug.LogError(ex.ToString());
                OutdateEvent();
            }
        }

        private void OutdateEvent()
        {
            outDateEvent?.Invoke();
            Debug.LogError("OutdateEvent was triggered");
        }

        [ContextMenu("��ӡ���ܵĽ��")]
        public void TryDecode()
        {
            Decode(File.ReadAllText(timeLimiterJsonPath));
        }

        /// <summary>
        /// ����
        /// </summary> 
        public string Decode(string timeLimiterDataStr_Code)
        {
            string timeLimiterDataStr = Decrypt(timeLimiterDataStr_Code);

            //Debug.Log(timeLimiterDataStr);

            return timeLimiterDataStr;
        }

        /// <summary>
        /// ����
        /// </summary> 
        public string Encode(string timeLimiterDataStr)
        {
            string timeLimiterDataStr_Code = Encrypt(timeLimiterDataStr);

            return timeLimiterDataStr_Code;
        }

#endregion

        #region AES �����㷨

        [Header("baseKey �� baseIv �������������� key �� iv������ʹ��Ӣ�ĺ��������")]
        [Header("ÿ����Ҫ���ܵ���Ŀ������ʹ�ò�ͬ��key��iv�����ص㱣�����ⶪʧ��й��")]
        public string baseKey ="youhavetochangethisdefaultkey";
        public string baseIv= "youhavetochangethisdefaultiv";

        /// <summary>
        /// ʵ��һ���̶���ת������������ baseKey ת�� key��baseIv ת�� iv
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
    /// ע����ΪPlayerPrefs�洢ʱ���ɴ洢���1MB��С������
    /// </summary>
    [System.Serializable]
    public class TimeLimiterData
    {
        /// <summary>
        /// ��ʼ��ʱ��-----����һ��ê�㣬��¼һ������׼ȷ�ġ���ʵ�ġ����ᵹ�˵�ʱ�䣬��Ҳ��ˣ�����ʹ��Initialize�����������޷����£�ʼ��ͣ����һ��������Ľ׶�
        /// </summary>
        public string InitializeTime;

        /// <summary>
        /// ����ʱ��------�ֶ��޸�
        /// </summary>
        public string OutdateTime;

        /// <summary>
        /// ����һ�δ򿪵�ʱ��------��һ��׼ȷ����Ϊ�ͻ���ʱ����ܻᱻ�����ֶ��޸�
        /// </summary>
        public string CurrentTime;

        /// <summary>
        /// ʣ�����ʱ�䣨�룩�����ڸ���У�飬
        /// ��Ϊʹ������Ȼ�п���ͨ��ÿ����ǰ����һ���ʱ�䣬���ﵽ����ʹ�õ�Ч������Ȼ�������ǿ��У������������Ǳ�Ҫ��
        /// ÿ��Checkʱֻ����٣����������¼���
        /// </summary>
        public string remainTime;
    }
     
}
