<?xml version="1.0" encoding="utf-8"?>
<!-- 
© Mindville
-->
<ScanPattern xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <Version>1.1.0</Version>
  <PatternID>TEHIK-Linux-2-mySQL</PatternID>
  <OrderNr>206</OrderNr>
  <ProcessType>SSHExecute</ProcessType>
  <PatternType>Application</PatternType>
  <ApplicationName>mysql</ApplicationName>
  <Processing><![CDATA[
    using System;
    using System.Collections.Generic;
    using Insight.Discovery.Tools;
    using Insight.Discovery.InfoClasses;
    using Insight.Discovery.ProviderClasses;
    using Insight.Discovery.InfoClasses.CommandResult.ResultTypes;
    
    namespace Insight.Discovery {
      public class PatternExec {        
        public void PerformAction(object[] parameters)
        {
            try
            {
                HostInfo host = ((HostInfo)parameters[2]);
                SSHProvider sshProvider = (SSHProvider)parameters[1];
                SSHExecuteResult sshExecuteResult;
                string internalCommand;
                string commandResult;

                if (!host.ApplicationServices.IsNullOrEmpty())
                {
                    Server InstanceInfo = new Server() { config = "", version = "", ip = "", port = "", status = "", uptime = ""};
                    ApplicationServiceInfo Service;

                    // Running MariaDB/MySQL instance version
                    internalCommand = @"mysql -u $$login$$ -p$$password$$ -e ""select version();""";
                    sshExecuteResult = (SSHExecuteResult)sshProvider.ExecuteCommand(internalCommand);
                    commandResult = sshExecuteResult;
                    sshExecuteResult.LogResult();

                    if (!string.IsNullOrEmpty(commandResult) && commandResult.Contains("version")) {
                        if (commandResult.Contains("--+\r\n")) // result containing frame
                        {
                            string[] lines = commandResult.Replace("\r", "").Split('\n');

                            for (int i = 1; i < lines.Length; i++)
                            {
                                if (!string.IsNullOrEmpty(lines[i]) && !lines[i].Contains("version") && lines[i].Contains("|"))
                                {
                                    InstanceInfo.version = lines[i].Replace("|", "").Trim();
                                }
                            }
                        }
                        else // without frames
                        {
                            InstanceInfo.version = commandResult.Split('\n')[1].Trim();
                        }

                        if (InstanceInfo.version.Contains("-Maria")) {
                            InstanceInfo.version = InstanceInfo.version.Split("-")[0];
                            Service = host.ApplicationServices.Find(o => o.Name.ToLower().Contains("mariadb"));
                        }
                        else {
                            Service = host.ApplicationServices.Find(o => o.Name.ToLower().Contains("mysql"));
                        }


                        // Run following code if we got service
                        if (Service != null) {
                            // Get service status
                            InstanceInfo.status = Service.Status;

                            // Get service uptime
                            if (InstanceInfo.status == "Running") {
                                internalCommand = "ps -o etime= -p `service " + Service.Name + " status | grep -i pid | grep -Po '[0-9]+'`";
                                sshExecuteResult = (SSHExecuteResult)sshProvider.ExecuteCommand(internalCommand);
                                commandResult = sshExecuteResult;
                                sshExecuteResult.LogResult();

                                if (!commandResult.Contains("error")) {
                                    string[] lines = commandResult.Split('\n');
                                    for (int l = 0; l < lines.Length; l++)
                                    {
                                        if (lines[l].Contains("Redirecting") || lines[l].Contains("ps ")) { continue; }
                                        else if (lines[l].Contains(":")) {
                                            InstanceInfo.uptime = lines[l].Trim();
                                        }
                                    }

                                    if (InstanceInfo.uptime.Contains("-")) {
                                        InstanceInfo.uptime = InstanceInfo.uptime.Replace("-", "days ");
                                    }
                                }
                            }


                            // Get information from configuration files
                            internalCommand = @"sudo grep '^#\?port\|bind-address\|!include' /etc/my.cnf";
                            sshExecuteResult = (SSHExecuteResult)sshProvider.ExecuteCommand(internalCommand);
                            commandResult = sshExecuteResult;
                            // Use alternative configuration file directory
                            if (commandResult.Contains("No such file")) {
                                internalCommand = @"sudo grep '^#\?port\|bind-address\|!include' /etc/mysql/my.cnf";
                                sshExecuteResult = (SSHExecuteResult)sshProvider.ExecuteCommand(internalCommand);
                                commandResult = sshExecuteResult;
                            }

                            // Process output and map information
                            if (!commandResult.Contains("No such file") && !string.IsNullOrEmpty(commandResult) && (commandResult.Contains("=") || commandResult.Contains("!include"))) {
                                string tempIp = "";
                                string tempPort = "";
                                string tempConfig = "";

                                // Process output and map information
                                GetIpAndPort(commandResult, ref tempIp, ref tempPort, ref tempConfig);
                                InstanceInfo.ip = tempIp;
                                InstanceInfo.port = tempPort;
                                InstanceInfo.config = tempConfig;

                                // Try again if port and ip numbers weren't found, but located another configuration file
                                if (string.IsNullOrEmpty(InstanceInfo.ip) && string.IsNullOrEmpty(InstanceInfo.port) && !string.IsNullOrEmpty(InstanceInfo.config)) {
                                    internalCommand = @"sudo grep -h '^#\?port\|bind-address\|!include' " + InstanceInfo.config;
                                    sshExecuteResult = (SSHExecuteResult)sshProvider.ExecuteCommand(internalCommand);
                                    commandResult = sshExecuteResult;

                                    if (!string.IsNullOrEmpty(commandResult) && commandResult.Contains("=")) {
                                        GetIpAndPort(commandResult, ref tempip, ref tempport, ref tempconfig);
                                    }
                                }
                            }

                            // Set defaults if not found
                            if (string.IsNullOrEmpty(InstanceInfo.port)) { InstanceInfo.port = "3306"; }
                            if (string.IsNullOrEmpty(InstanceInfo.ip)) { InstanceInfo.ip = "0.0.0.0"; }


                            // Map information to host object
                            DatabaseInfo dbi = new DatabaseInfo() { DatabaseInstanceName = InstanceInfo.ip, DatabaseInstancePort = Convert.ToInt32(InstanceInfo.port), ExtendedInformations = new List<ExtendedInformation>() };
                            string servername = string.IsNullOrEmpty(host.FQDN) ? host.Hostname : host.FQDN;
                            dbi.ExtendedInformations.Add(new ExtendedInformation() { Name = "Server Name", Value = servername });
                            dbi.ExtendedInformations.Add(new ExtendedInformation() { Name = "Status", Value = InstanceInfo.status });
                            dbi.ExtendedInformations.Add(new ExtendedInformation() { Name = "Uptime", Value = InstanceInfo.uptime });
                            dbi.ExtendedInformations.Add(new ExtendedInformation() { Name = "Version", Value = InstanceInfo.version });

                            // Add information to host
                            if (host.Databases == null)
                                host.Databases = new List<DatabaseInfo>();
                            host.Databases.Add(dbi);

                            // Add information to application
                            ApplicationInfo mysql = null;
                            if (!host.Applications.IsNullOrEmpty()) {
                                if (Service.Name.Contains("maria")) {
                                    mysql = host.Applications.Find(o => o.Name.ToLower().Contains("mariadb") && o.Version == InstanceInfo.version && o.Description.ToLower().Contains("server"));
                                }
                                else {
                                    mysql = host.Applications.Find(o => o.Name.ToLower().Contains("mysql") && o.Version == InstanceInfo.version && o.Description.ToLower().Contains("server"));
                                }
                            }

                            if (mysql.ReferencedDatabases == null)
                                mysql.ReferencedDatabases = new List<string>();

                            mysql.ReferencedDatabases.Add(dbi.ObjectHash);


                            // Connect to server and map databases
                            if (InstanceInfo.status == "Running") {
                                internalCommand = @"mysql -u $$login$$ -p$$password$$ -e ""SELECT TABLE_SCHEMA AS 'Database name', Round(Sum(DATA_LENGTH + INDEX_LENGTH) / 1024 / 1024, 0) AS 'Size (MB)' FROM information_schema.TABLES GROUP BY TABLE_SCHEMA;""";
                                sshExecuteResult = (SSHExecuteResult)sshProvider.ExecuteCommand(internalCommand, false);
                                commandResult = sshExecuteResult;
                                sshExecuteResult.LogResult();

                                if (!commandResult.Contains("ERROR") && !commandResult.Contains("Usage:") && !commandResult.Contains("bash:")) {
                                    // Map databases for instance
                                    AddDbInformation(commandResult, servername, InstanceInfo.version, ref host);
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            { LogService.Instance.LogDebug("Error getting information for running mysql databases", ex); }

        }

        private void AddDbInformation(string input, string servername, string version, ref HostInfo host)
        {
            try
            {
                string sizeValue;
                if (input.Contains("--+\r\n")) // result containing frame
                {
                    string[] lines = input.Replace("\r", "").Split('\n');

                    for (int i = 1; i < lines.Length; i++)
                    {
                        if (!string.IsNullOrEmpty(lines[i]) && !lines[i].Contains("Database") && lines[i].Contains("|"))
                        {
                            string[] col = lines[i].Split('|');

                            if (col.Length == 4)
                            {
                                sizeValue = col[1].Trim();
                                try
                                {
                                    int size = int.Parse(sizeValue); // size in Mb

                                    sizeValue = size.ToString();
                                }
                                catch
                                {
                                    //
                                }

                                DatabaseInfo dbi = new DatabaseInfo() { Name = col[0].Trim(), ExtendedInformations = new List<ExtendedInformation>() };
                                dbi.ExtendedInformations.Add(new ExtendedInformation() { Name = "Size", Type = "Integer", Value = sizeValue });
                                dbi.ExtendedInformations.Add(new ExtendedInformation() { Name = "Server Name", Value = servername });
                                dbi.ExtendedInformations.Add(new ExtendedInformation() { Name = "Version", Value = version });

                                host.Databases.Add(dbi);
                            }
                        }
                    }
                }
                else // without frames
                {
                    string[] lines = input.Split('\n');

                    for (int i = 1; i < lines.Length; i++)
                    {
                        if (!string.IsNullOrEmpty(lines[i]))
                        {
                            string[] col = lines[i].Split('\t');

                            if (col.Length == 2)
                            {
                                sizeValue = col[1].Trim();
                                try
                                {
                                    int size = int.Parse(sizeValue); // size in Mb
                                    //int size = int.Parse(sizeValue) / 1024; // size in Gb

                                    sizeValue = size.ToString();
                                }
                                catch
                                {
                                    //
                                }

                                DatabaseInfo dbi = new DatabaseInfo() { Name = col[0].Trim(), ExtendedInformations = new List<ExtendedInformation>() };
                                dbi.ExtendedInformations.Add(new ExtendedInformation() { Name = "Size", Type = "Integer", Value = sizeValue });
                                dbi.ExtendedInformations.Add(new ExtendedInformation() { Name = "Server Name", Value = servername });
                                dbi.ExtendedInformations.Add(new ExtendedInformation() { Name = "Version", Value = version });

                                host.Databases.Add(dbi);
                            }
                        }
                    }
                }
            }
            catch (Exception eex)
            {
                LogService.Instance.LogDebug("Error getting Extended Information for running mysql databases", eex);
            }
        }

        private static void GetIpAndPort(string input, ref string ip, ref string port, ref string config)
        {
            string[] lines = input.Split('\n');
            for (int x = 0; x < lines.Length; x++) {
                if ((!lines[x].StartsWith("#") || !lines[x].StartsWith(";")) && lines[x].Contains("port") && lines[x].Contains("=")) {
                    port = lines[x].Split("=")[1].Trim();
                }
                if ((!lines[x].StartsWith("#") || !lines[x].StartsWith(";")) && lines[x].Contains("bind") && lines[x].Contains("=")) {
                    ip = lines[x].Split("=")[1].Trim();
                }
                if ((!lines[x].StartsWith("#") || !lines[x].StartsWith(";")) && lines[x].Contains("includedir")) {
                    config = lines[x].Split(" ")[1];
                    if (!config.EndsWith("/")) { config = config + "/*.cnf"; }
                }
                if ((!lines[x].StartsWith("#") || !lines[x].StartsWith(";")) && lines[x].Contains("include")) {
                    config = lines[x].Split(" ")[1];
                }
            }
        }

        // Class for Instance object info
        public class Server
        {
            public string config { get; set; }
            public string version { get; set; }
            public string port { get; set; }
            public string status { get; set; }
            public string ip { get; set; }
            public string uptime { get; set; }
        }
   
      }
    }
    ]]></Processing>
</ScanPattern>
