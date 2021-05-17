<?xml version="1.0" encoding="utf-8"?>
<!-- 
© Mindville
-->
<ScanPattern xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <Version>1.2.0</Version>
  <PatternID>TEHIK-Linux-1-postgreSQL</PatternID>
  <OrderNr>205</OrderNr>
  <ProcessType>SSHExecute</ProcessType>
  <PatternType>Application</PatternType>
  <ApplicationName>postgresql</ApplicationName>
  <Processing><![CDATA[
    using System;
    using System.Collections.Generic;
    using System.Linq;
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
                // Variable to check whether we need to use additional code for Patroni
                bool isPatroni = false;

                if (!host.ApplicationServices.IsNullOrEmpty())
                {
                    var ServiceNames = new List<string>();

                    // Does postgresql run on Patroni?
                    ApplicationInfo patroni = host.Applications.Find(o => o.Name == ("patroni") && o.Description.ToLower().Contains("postgresql"));
                    if (patroni != null) {
                        ServiceNames.Add(host.ApplicationServices.Find(o => o.Name == "patroni").Name);
                        isPatroni = true;
                    }
                    else {
                        List<ApplicationServiceInfo> Services = host.ApplicationServices.FindAll(o => o.Name.Contains("postgresql-") || o.Name == "postgresql");
                        // Get every service name in string and add them to ServiceNames list
                        foreach (ApplicationServiceInfo i in Services) { ServiceNames.Add(i.Name); }
                    }


                    // Find information for each instance in ServiceNames
                    for (int i = 0; i < ServiceNames.Count; i++)
                    {
                        Server InstanceInfo = new Server() { data_dir = "", bin_dir = "", version = "", ip = "", port = "", status = "", uptime = ""};
                        string[] lines;
                        string[] lines2;
                        // Variable to check whether localhost is allowed to connect to DB.
                        bool nolocalhost = false;


                        // Command only for running instance
                        internalCommand = "ps aux | grep `service " + ServiceNames[i] + @" status | grep -i pid | grep -Po '[0-9]+'` 2>&1 | grep -Po '/usr/.*'";
                        sshExecuteResult = (SSHExecuteResult)sshProvider.ExecuteCommand(internalCommand);
                        commandResult = sshExecuteResult;
                        sshExecuteResult.LogResult();

                        // Alternative commands
                        if (string.IsNullOrEmpty(commandResult) || !commandResult.Contains("-D "))
                        {
                            internalCommand = "service " + ServiceNames[i] + @" status | awk '$1==""Drop-In:""{print $2}' | while read line; do grep -R 'PGDATA' ""$line""; done | sed -n 's/.*PGDATA=//p'";
                            // Overwrite command if we have Patroni
                            if (isPatroni) {
                                internalCommand = "service " + ServiceNames[i] + @" status | awk '$1==""Loaded:""{print $3}' | grep -Po '(\/[a-zA-Z]*[0-9]*[.-]*[a-zA-Z]*[0-9]*)*(.service)' | while read line; do grep -Po '(\/[a-zA-Z]*[0-9]*[._-]*[a-zA-Z]*[0-9]*)*(.yml)$' ""$line""; done";
                            }
                            sshExecuteResult = (SSHExecuteResult)sshProvider.ExecuteCommand(internalCommand);
                            commandResult = sshExecuteResult;
                            sshExecuteResult.LogResult();
                        }
                        lines = commandResult.Split('\n');
                        if (string.IsNullOrEmpty(commandResult) || lines[lines.Length - 1].Contains("service ") || lines[lines.Length - 1].Contains("Redirecting"))
                        {
                            internalCommand = "service " + ServiceNames[i] + @" status | awk '$1==""Loaded:""{print $3}' | grep -Po '(\/[a-zA-Z]*[0-9]*[.-]*[a-zA-Z]*[0-9]*)*(.service)' | while read line; do grep -R 'PGDATA' ""$line""; done | sed -n 's/.*PGDATA=//p'";
                            sshExecuteResult = (SSHExecuteResult)sshProvider.ExecuteCommand(internalCommand);
                            commandResult = sshExecuteResult;
                            sshExecuteResult.LogResult();
                        }
                        lines = commandResult.Split('\n');


                        for (int o = 0; o < lines.Length; o++) {
                            if (lines[o].Contains("Redirec") || lines[o].Contains("service ") || lines[o].Contains("ps ")) { continue; }
                            else if (lines[o].Contains("/")) {
                                InstanceInfo.data_dir = lines[o];
                            }
                        }


                        // If we got output from ps aux
                        if (!string.IsNullOrEmpty(InstanceInfo.data_dir) && InstanceInfo.data_dir.Contains("-D "))
                        {
                            string[] columns;
                            if (InstanceInfo.data_dir.Contains(" --")) { columns = InstanceInfo.data_dir.Split(" --"); }
                            else { columns = InstanceInfo.data_dir.Split(" -"); }
                            
                            for (int x = 0; x < columns.Length; x++)
                            {
                                // If we found postgresql data and bin directories, listen port and ip, then end loop
                                if (!string.IsNullOrEmpty(InstanceInfo.data_dir) && !string.IsNullOrEmpty(InstanceInfo.bin_dir) && !string.IsNullOrEmpty(InstanceInfo.port) && !string.IsNullOrEmpty(InstanceInfo.ip)) { break; }
                                if (columns[x].Contains("-D ")) {
                                    int indexD = columns[x].IndexOf("-D");
                                    int indexusr = columns[x].IndexOf("/usr/");
                                    InstanceInfo.bin_dir = columns[x].Substring(indexusr, indexD - indexusr).Trim();
                                    InstanceInfo.data_dir = columns[x].Substring(indexD + 2).Trim();
                                }
                                else if (columns[x].Contains("D ")) {
                                    int indexusr = columns[0].IndexOf("/usr/");
                                    InstanceInfo.bin_dir = columns[0].Substring(indexusr).Trim();
                                    InstanceInfo.data_dir = columns[x].Substring(columns[x].IndexOf("D") + 1).Trim();
                                }
                                else if (columns[x].Contains("port")) {
                                    InstanceInfo.port = columns[x].Substring(columns[x].IndexOf("=") + 1).Trim();
                                }
                                else if (columns[x].Contains("listen_addresses")) {
                                    InstanceInfo.ip = columns[x].Substring(columns[x].IndexOf("=") + 1).Trim();
                                    nolocalhost = true;
                                }
                                else if (columns[x].Contains("p ")) {
                                    InstanceInfo.port = columns[x].Substring(columns[x].IndexOf("p") + 1).Trim();
                                }
                            }
                        }

                        // If we got template file from Patroni
                        if (InstanceInfo.data_dir.Contains(".yml")) {
                            int indextemp = InstanceInfo.data_dir.IndexOf("/");
                            InstanceInfo.data_dir = InstanceInfo.data_dir.Substring(indextemp, InstanceInfo.data_dir.IndexOf(".yml") + 4 - indextemp);
                            internalCommand = "sudo grep -A5 'postgresql:' " + InstanceInfo.data_dir + @" | grep 'listen\|data_dir\|bin_dir'";
                            sshExecuteResult = (SSHExecuteResult)sshProvider.ExecuteCommand(internalCommand);
                            commandResult = sshExecuteResult;
                            sshExecuteResult.LogResult();
                            lines = commandResult.Split('\n');

                            for (int k = 0; k < lines.Length; k++)
                            {
                                string temporary;
                                if (lines[k].Contains("listen")) {
                                    temporary = lines[k].Replace("listen:", "").Trim();
                                    InstanceInfo.ip = temporary.Split(":")[0];
                                    InstanceInfo.port = temporary.Split(":")[1];
                                }
                                else if (lines[k].Contains("data_dir")) {
                                    InstanceInfo.data_dir = lines[k].Replace("data_dir:", "").Trim();
                                }
                                else if (lines[k].Contains("bin_dir")) {
                                    InstanceInfo.bin_dir = lines[k].Replace("bin_dir:", "").Trim();
                                }
                            }
                        }

                        // Continue to next instance if directory wasn't found
                        if (string.IsNullOrEmpty(InstanceInfo.data_dir)) { continue; }
                        //Remove unwanted characters/symbols if there are any
                        int firstslash = InstanceInfo.data_dir.IndexOf("/");
                        if (!InstanceInfo.data_dir.EndsWith("/")) {
                            int lastslash = InstanceInfo.data_dir.LastIndexOf("/");
                            int indexmain = InstanceInfo.data_dir.LastIndexOf("main");
                            int indexdata = InstanceInfo.data_dir.LastIndexOf("data");
                            if (lastslash > indexdata || lastslash > indexmain) {
                                InstanceInfo.data_dir = InstanceInfo.data_dir.Substring(firstslash, lastslash + 1 - firstslash);
                            }
                            else if (indexmain != -1) {
                                InstanceInfo.data_dir = InstanceInfo.data_dir.Substring(firstslash, indexmain + 4 - firstslash) + "/";
                            }
                            else {
                                InstanceInfo.data_dir = InstanceInfo.data_dir.Substring(firstslash, indexdata + 4 - firstslash) + "/";
                            }
                        }
                        else { InstanceInfo.data_dir = InstanceInfo.data_dir.Substring(firstslash); }


                        if (!isPatroni && (string.IsNullOrEmpty(InstanceInfo.port) || string.IsNullOrEmpty(InstanceInfo.ip)))
                        {
                            internalCommand = @"sudo grep '^#\?port\|listen_addresses' " + InstanceInfo.data_dir + "postgresql.conf";
                            sshExecuteResult = (SSHExecuteResult)sshProvider.ExecuteCommand(internalCommand);
                            commandResult = sshExecuteResult;
                            if (commandResult.Contains("No such file")) { continue; }

                            lines2 = commandResult.Split('\n');
                            for (int m = 0; m < lines2.Length; m++)
                            {
                                if (!lines2[m].StartsWith("#") && lines2[m].Contains("port") && string.IsNullOrEmpty(InstanceInfo.port)) {
                                    InstanceInfo.port = lines2[m].Split("=")[1].Trim();
                                }
                                else if (!lines2[m].StartsWith("#") && lines2[m].Contains("listen") && lines2[m].Contains("'*'") && string.IsNullOrEmpty(InstanceInfo.ip))
                                {
                                    InstanceInfo.ip = "0.0.0.0";
                                }
                                else if (!lines2[m].StartsWith("#") && lines2[m].Contains("listen") && string.IsNullOrEmpty(InstanceInfo.ip))
                                {
                                    InstanceInfo.ip = lines2[m].Split("=")[1].Trim().Replace("'", "");
                                    nolocalhost = true;
                                }
                            }
                            // Set default values if empty
                            if (string.IsNullOrEmpty(InstanceInfo.port)) { InstanceInfo.port = "5432"; }
                            if (string.IsNullOrEmpty(InstanceInfo.ip)) { InstanceInfo.ip = "localhost"; }

                            // Remove unwanted comments
                            if (InstanceInfo.port.Contains("#")) { InstanceInfo.port = InstanceInfo.port.Substring(0, InstanceInfo.port.IndexOf("#")); }
                            if (InstanceInfo.ip.Contains("#")) { InstanceInfo.ip = InstanceInfo.ip.Substring(0, InstanceInfo.ip.IndexOf("#")); }
                        }


                        // If no IP or Port was found, continue to next instance.
                        if (string.IsNullOrEmpty(InstanceInfo.port) && string.IsNullOrEmpty(InstanceInfo.ip)) { continue; }


                        // Get PostgreSQL version
                        if (InstanceInfo.bin_dir.EndsWith("bin")) {
                            InstanceInfo.bin_dir = InstanceInfo.bin_dir + "/postgres";
                        }
                        internalCommand = InstanceInfo.bin_dir + " -V";
                        if (string.IsNullOrEmpty(InstanceInfo.bin_dir))
                            internalCommand = "`service " + ServiceNames[i] + @" status | awk '$1==""Loaded:""{print $3}' | grep -Po '(\/[a-zA-Z]*[0-9]*[.-]*[a-zA-Z]*[0-9]*)*(.service)' | while read line; do grep 'ExecStart' ""$line""; done | sed -n 's/.*ExecStart=//p' | awk '{print $1}'` -V";
                        sshExecuteResult = (SSHExecuteResult)sshProvider.ExecuteCommand(internalCommand);
                        commandResult = sshExecuteResult;
                        sshExecuteResult.LogResult();
                        if (commandResult.Contains("(PostgreSQL)")) {
                            InstanceInfo.version = commandResult.Substring(commandResult.IndexOf("SQL)") + 4).Trim();
                        }
                        else if (ServiceNames[i].Contains("sql-")) {
                            string version = ServiceNames[i].Split("-")[1].Trim();
                            if (!version.Contains(".") && version[0] != '1') {
                                InstanceInfo.version = version[0] + "." + version[1];
                            }
                            else { InstanceInfo.version = version; }
                            InstanceInfo.version = host.Applications.Find(o => o.Name.Contains("postgres") && o.Version.StartsWith(InstanceInfo.version) && o.Description.ToLower().Contains("server")).Version;
                        }


                        // Get instance status
                        InstanceInfo.status = host.ApplicationServices.Find(o => o.Name.Contains(ServiceNames[i])).Status;
                                
                        // Get service uptime if it's running. 
                        if (InstanceInfo.status == "Running")
                        {
                            internalCommand = "ps -o etime= -p `service " + ServiceNames[i] + @" status | grep -i pid | grep -Po '[0-9]+'`";
                            sshExecuteResult = (SSHExecuteResult)sshProvider.ExecuteCommand(internalCommand);
                            commandResult = sshExecuteResult;
                            sshExecuteResult.LogResult();

                            if (!commandResult.Contains("error")) {
                                lines2 = commandResult.Split('\n');
                                for (int l = 0; l < lines2.Length; l++)
                                {
                                    if (lines2[l].Contains("Redirecting") || lines2[l].Contains("ps ")) { continue; }
                                    else if (lines2[l].Contains(":")) {
                                        InstanceInfo.uptime = lines2[l].Trim();
                                    }
                                }

                                if (InstanceInfo.uptime.Contains("-")) {
                                    InstanceInfo.uptime = InstanceInfo.uptime.Replace("-", "days ");
                                }
                            }
                        }

                        // Check whether we missed symbols in port
                        InstanceInfo.port = new string(InstanceInfo.port.Where(c => char.IsDigit(c)).ToArray());
                        string servername = string.IsNullOrEmpty(host.FQDN) ? host.Hostname : host.FQDN;

                        // Map information to host object
                        DatabaseInfo dbi = new DatabaseInfo() { DatabaseInstanceName = InstanceInfo.ip, DatabaseInstancePort = Convert.ToInt32(InstanceInfo.port), ExtendedInformations = new List<ExtendedInformation>() };
                        dbi.ExtendedInformations.Add(new ExtendedInformation() { Name = "Server Name", Value = servername });
                        dbi.ExtendedInformations.Add(new ExtendedInformation() { Name = "Status", Value = InstanceInfo.status });
                        dbi.ExtendedInformations.Add(new ExtendedInformation() { Name = "Uptime", Value = InstanceInfo.uptime });
                        dbi.ExtendedInformations.Add(new ExtendedInformation() { Name = "Version", Value = InstanceInfo.version });

                        // Add information to host.
                        if (host.Databases == null)
                            host.Databases = new List<DatabaseInfo>();
                        host.Databases.Add(dbi);

                        // Add reference to postgresql and/or patroni server application with certain version.
                        ApplicationInfo postgres = host.Applications.Find(o => o.Name.Contains("postgres") && o.Version == InstanceInfo.version && o.Description.ToLower().Contains("server"));

                        if (postgres.ReferencedDatabases == null)
                            postgres.ReferencedDatabases = new List<string>();
                        if (isPatroni && patroni.ReferencedDatabases == null)
                            patroni.ReferencedDatabases = new List<string>();

                        if (isPatroni) { patroni.ReferencedDatabases.Add(dbi.ObjectHash); }
                        postgres.ReferencedDatabases.Add(dbi.ObjectHash);


                        // Get databases with psql client command, login and password are stored encrypted in credentials file
                        if (InstanceInfo.status == "Running") {
                            internalCommand = @"PGPASSWORD=$$password$$ psql -U $$login$$ -h localhost -p " + InstanceInfo.port + @" -c ""\l+""";
                            if (nolocalhost) { internalCommand = @"PGPASSWORD=$$password$$ psql -U $$login$$ -h " + InstanceInfo.ip + " -p " + InstanceInfo.port + @" -c ""\l+"""; }
                            sshExecuteResult = (SSHExecuteResult)sshProvider.ExecuteCommand(internalCommand, false);
                            commandResult = sshExecuteResult;
                            sshExecuteResult.LogResult();

                            if (!commandResult.Contains("error")) {
                                // Map databases for instance
                                AddDbInformation(commandResult, servername, InstanceInfo.version, ref host);
                            }
                        }
                        
                    }
                }

            }
            catch (Exception ex)
            { LogService.Instance.LogDebug("Error getting information for running PostreSQL databases", ex); }
        }

        private void AddDbInformation(string input, string servername, string version, ref HostInfo host)
        {
            string[] lines2 = input.Split('\n');
            if (lines2.Length > 3)
            {
                for (int n = 3; n < lines2.Length; n++)
                {
                    if (lines2[n].Contains("|"))
                    {
                        DatabaseInfo dbi2 = new DatabaseInfo() { ExtendedInformations = new List<ExtendedInformation>() };
                        dbi2.ExtendedInformations.Add(new ExtendedInformation() { Name = "Server Name", Value = servername });
                        dbi2.ExtendedInformations.Add(new ExtendedInformation() { Name = "Version", Value = version });
                        string[] cols = lines2[n].Split('|');

                        for (int x = 0; x < cols.Length; x++)
                        {
                            if (!string.IsNullOrEmpty(cols[x].Trim()))
                            {
                                switch (x)
                                {
                                    case 0:
                                        dbi2.Name = cols[x].Trim();
                                        break;
                                    case 1:
                                        break;
                                    case 2:
                                        dbi2.ExtendedInformations.Add(
                                            new ExtendedInformation() { Name = "Encoding", Value = cols[x].Trim() });
                                        break;
                                    case 3:
                                        break;
                                    case 4:
                                        break;
                                    case 5:
                                        break;
                                    case 6:
                                        string[] sizeParts = cols[x].Trim().Split(' ');
                                        if (sizeParts.Length == 2)
                                        {
                                            long size = 0;
                                            long.TryParse(sizeParts[0].Trim(), out size);

                                            if (size > 0)
                                            {
                                                switch (sizeParts[1].Trim().ToLower())
                                                {
                                                    case "byte":
                                                        size = size / 1024 / 1024;
                                                        break;
                                                    case "kb":
                                                        size = size / 1024;
                                                        break;
                                                    case "gb":
                                                        size = size * 1024;
                                                        break;
                                                    case "tb":
                                                        size = size * 1024 * 1024;
                                                        break;
                                                }
                                            }
                                            dbi2.ExtendedInformations.Add(
                                                new ExtendedInformation()
                                                {
                                                    Name = "Size",
                                                    Type = "Integer",
                                                    Value = size.ToString()
                                                });
                                        }
                                        break;
                                    case 7:
                                        break;
                                    case 8:
                                        dbi2.ExtendedInformations.Add(
                                            new ExtendedInformation() { Name = "Description", Value = cols[x].Trim() });
                                        break;
                                }
                            }
                        }                  
                        host.Databases.Add(dbi2);
                    }
                }
            }
        }
        // Class for Instance object info.
        public class Server
        {
            public string data_dir { get; set; }
            public string bin_dir { get; set; }
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