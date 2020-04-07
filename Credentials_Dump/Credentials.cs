using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Permissions;

namespace Credentials_Dump
{

    public class Credential : IDisposable
    {
        private static readonly object LockObject = new object();
        private static readonly SecurityPermission UnmanagedCodePermission;
        private string description;
        private DateTime lastWriteTime;
        private string password;
        private PersistenceType persistenceType;
        private string target;
        private CredentialType type;
        private string username;
        static Credential()
        {
            lock (LockObject)
            {
                UnmanagedCodePermission = new SecurityPermission(SecurityPermissionFlag.UnmanagedCode);
            }
        }

        public Credential(string username, string password, string target, CredentialType type)
        {
            Username = username;
            Password = password;
            Target = target;
            Type = type;
            PersistenceType = PersistenceType.Session;
            lastWriteTime = DateTime.MinValue;
        }

        public string Username
        {
            get { return username; }
            set { username = value; }
        }

        public string Password
        {
            get { return password; }
            set { password = value; }
        }

        public string Target
        {
            get { return target; }
            set { target = value; }
        }

        public string Description
        {
            get { return description; }
            set { description = value; }
        }

        public DateTime LastWriteTime
        {
            get { return LastWriteTimeUtc.ToLocalTime(); }
        }

        public DateTime LastWriteTimeUtc
        {
            get { return lastWriteTime; }
            private set { lastWriteTime = value; }
        }

        public CredentialType Type
        {
            get { return type; }
            set { type = value; }
        }

        public PersistenceType PersistenceType
        {
            get { return persistenceType; }
            set { persistenceType = value; }
        }

        public void Dispose() { }

        public bool Load()
        {
            UnmanagedCodePermission.Demand();


            bool result = NativeMethods.CredRead(Target, Type, 0, out IntPtr credPointer);
            if (!result)
                return false;

            using (NativeMethods.CriticalCredentialHandle credentialHandle = new NativeMethods.CriticalCredentialHandle(credPointer))
            {
                LoadInternal(credentialHandle.GetCredential());
            }

            return true;
        }

        public static IEnumerable<Credential> LoadAll()
        {
            UnmanagedCodePermission.Demand();

            IEnumerable<NativeMethods.CREDENTIAL> creds = NativeMethods.CredEnumerate();
            List<Credential> credlist = new List<Credential>();

            foreach (NativeMethods.CREDENTIAL cred in creds)
            {
                Credential fullCred = new Credential(cred.UserName, null, cred.TargetName, (CredentialType)cred.Type);
                if (fullCred.Load())
                    credlist.Add(fullCred);
            }

            return credlist;
        }

        internal void LoadInternal(NativeMethods.CREDENTIAL credential)
        {
            Username = credential.UserName;

            if (credential.CredentialBlobSize > 0)
            {
                Password = Marshal.PtrToStringUni(credential.CredentialBlob, credential.CredentialBlobSize / 2);
            }

            Target = credential.TargetName;
            Type = (CredentialType)credential.Type;
            PersistenceType = (PersistenceType)credential.Persist;
            Description = credential.Comment;
            LastWriteTimeUtc = DateTime.FromFileTimeUtc(credential.LastWritten);
        }
    }
}