<?xml version="1.0" encoding="utf-8"?>
<!-- 
© Atlassian
-->
<ScanPattern xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <Version>1.2.0</Version>
  <PatternID>TEHIK-Linux-3-nginx</PatternID>
  <OrderNr>250</OrderNr>
  <ProcessType>SSHExecute</ProcessType>
  <PatternType>Application</PatternType>
  <ApplicationName>nginx</ApplicationName>
  <Processing>
    <![CDATA[
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

                // Find Nginx service
                ApplicationServiceInfo nginxService = host.ApplicationServices.Find(o => o.Name == "nginx");

                if (nginxService != null) {
                    // Find all server Nginx applications
                    List<ApplicationInfo> nginxApp = host.Applications.FindAll(o => o.Name.ToLower().Contains("nginx") && o.Description.ToLower().Contains("server"));
                    // List for configuration files path
                    List<string> Paths = new List<string>();


                    // Find Nginx main configuration path
                    internalCommand = "nginx -V";
                    sshExecuteResult = (SSHExecuteResult)sshProvider.ExecuteCommand(internalCommand);
                    commandResult = sshExecuteResult;
                    sshExecuteResult.LogResult();

                    if (!string.IsNullOrEmpty(commandResult)) {
                      string[] line = commandResult.Split('\n');

                      for (int x = 0; x < line.Length; x++) {
                        if (line[x].Contains("conf-path=")) {
                          int start = line[x].IndexOf("conf-path=") + 10;
                          int end = line[x].IndexOf(" ", start);

                          Paths.Add(line[x].Substring(start, end - start));
                        }
                      }
                    }


                    if (Paths.Count > 0) {
                      // Get all of the included configuration files from main
                      internalCommand = "grep 'include' " + Paths[0];
                      sshExecuteResult = (SSHExecuteResult)sshProvider.ExecuteCommand(internalCommand);
                      commandResult = sshExecuteResult;

                      string[] lines = commandResult.Split('\n');
                      for (int i = 0; i < lines.Length; i++) {
                        if (!lines[i].StartsWith("#") && (lines[i].Contains("conf") || lines[i].Contains("site"))) {
                          int start2 = lines[i].IndexOf("include") + 7;
                          int end2 = lines[i].IndexOf(";");

                          Paths.Add(lines[i].Substring(start2, end2 - start2).Trim());
                        }
                      }

                      
                      // Get every enabled virtual hosts
                      string partCommand = "awk '/server *{/{c=1; print;next} c&&/{/{c++} c&&/}/{c--} c' ";
                      for (int i = 0; i < Paths.Count; i++) {
                        partCommand = partCommand + Paths[i] + " ";
                      }
                      internalCommand = partCommand + @"| grep -Po '(^[^#]*((server)\s*{$|[{}]|(listen|server_name|ssl|root|return)\s+)).*'";
                      sshExecuteResult = (SSHExecuteResult)sshProvider.ExecuteCommand(internalCommand);
                      commandResult = sshExecuteResult;


                      // Loop through each virtual host and map items
                      if (commandResult.Contains("server {")) {
                        string[] servers = commandResult.Split("server {");

                        for (int s = 0; s < servers.Length; s++) {
                          if (string.IsNullOrEmpty(servers[s])) { continue; }

                          string sname = "";
                          string sport = "";
                          string ssl = "";
                          string sroot = "";
                          GetServerInfo(servers[s], ref sname, ref sport, ref sroot, ref ssl);


                          if (string.IsNullOrEmpty(sname)) { continue; }
                          // If server name is referred as all, then replace it with Ethernet IPv4
                          else if (sname.Length < 3) {
                            sname = host.NetworkInterfaces.Find(o => o.DeviceID.Contains("eth")).IP4;
                          }


                          // Map information to host object
                          ApplicationInfo ngserver = new ApplicationInfo() { ExtendedInformations = new List<ExtendedInformation>() };
                          ngserver.ExtendedInformations.Add(new ExtendedInformation() { Name = "Web Name", Value = sname });
                          ngserver.ExtendedInformations.Add(new ExtendedInformation() { Name = "Port", Value = sport });
                          ngserver.ExtendedInformations.Add(new ExtendedInformation() { Name = "SSL", Value = ssl });
                          ngserver.ExtendedInformations.Add(new ExtendedInformation() { Name = "Status", Value = nginxService.Status });
                          ngserver.ExtendedInformations.Add(new ExtendedInformation() { Name = "Root", Value = sroot });

                          // Add information to host
                          host.Applications.TryAdd(ngserver);

                          // Add referenced application data
                          foreach (ApplicationInfo n in nginxApp) {
                              if (ngserver.ReferencedApplications == null)
                                  ngserver.ReferencedApplications = new List<string>();

                              ngserver.ReferencedApplications.Add(n.ObjectHash);
                          }

                        }
                      }

                    }

                }
            }
            catch (Exception ex)
            { LogService.Instance.LogDebug("Error getting Nginx Application Information", ex); }
        }

        private static void GetServerInfo(string input, ref string sname, ref string sport, ref string sroot, ref string ssl)
        {
          // Set ssl to false as default
          ssl = "false";

          // Maintain only main server configuration
          if (input.Contains("}")) {
            int removable = input.Split("}").Length - 1;

            if (removable > 0) {
              for (int i = 0; i < removable; i++) {
                int k1 = input.LastIndexOf("{");
                int k2 = input.LastIndexOf("}");
                
                input = input.Remove(k1, k2 - k1);
              }
            }
          }
          
          string[] lines = input.Split('\n');
          for (int x = 0; x < lines.Length; x++) {
            // Don't map virtual host if it returns 404 error
            if (lines[x].Contains("return") && lines[x].Contains("404")) {
              sname = null;
              break;
            }

            int i2;

            if (lines[x].Contains("listen")) {
              // Line listen contains name/ip of virtual host
              if (lines[x].Contains(":")) {
                int i1 = lines[x].LastIndexOf(":") + 1;
                i2 = lines[x].IndexOf(" ", i1);

                if (i2 == -1) {
                  i2 = lines[x].LastIndexOf(";");
                }

                sport = lines[x].Substring(i1, i2 - i1).Trim();

                int i3 = lines[x].LastIndexOf("listen") + 6;

                sname = lines[x].Substring(i3, i1 - i3).Trim();
                if (sname.Contains(":")) {
                  sname = "_";
                }
              }
              else {
                sport = lines[x].Replace("listen", "").TrimStart().TrimEnd();

                i2 = lines[x].IndexOf(" ");
                if (i2 == -1) {
                  i2 = lines[x].LastIndexOf(";");
                }

                sport = sport.Substring(0, i2).Trim();
              }

              // Line listen contains ssl
              if (lines[x].Contains("ssl")) {
                ssl = "true";
              }
            }
            else if (lines[x].Contains("root")) {
              int i1 = lines[x].IndexOf("root") + 4;

              sroot = lines[x].Substring(i1, lines[x].IndexOf(";") - i1).Trim();
            }
            else if (lines[x].Contains("ssl") && lines[x].Contains("on")) {
              ssl = "true";
            }
            else if (lines[x].Contains("server_name")) {
              sname = lines[x].Replace("server_name", "").TrimStart().TrimEnd();

              i2 = lines[x].IndexOf(" ");
              if (i2 == -1) {
                i2 = lines[x].LastIndexOf(";");
              }

              sname = sname.Substring(0, i2).Trim();
            }
          }
        }
     
      }
    }
    ]]>
  </Processing>
</ScanPattern>
