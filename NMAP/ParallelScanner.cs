using System.Collections.Generic;
using log4net;
using System.Data;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace NMAP
{
    public class ParallelScanner : IPScanner
    {
        protected virtual ILog log => LogManager.GetLogger(typeof(ParallelScanner));

        public virtual Task Scan(IPAddress[] ipAddrs, int[] ports) => 
            Task.WhenAll(ipAddrs.Select(a => ScanAddress(a, ports)));

        private async Task ScanAddress(IPAddress addr, int[] port)
        {
            var status = await PingAddr(addr);
            if (status != IPStatus.Success)
                return;
            var tasks = port.Select(p => CheckPort(addr, p)).ToArray();
            await Task.WhenAll(tasks);
        }

        protected async Task<IPStatus> PingAddr(IPAddress ipAddr, int timeout = 3000)
        {
            log.Info($"Pinging {ipAddr}");
            using (var ping = new Ping())
            {
                var res = await ping.SendPingAsync(ipAddr, timeout);
                log.Info($"Pinged {ipAddr}: {res.Status}");
                return res.Status;
            }
        }

        protected async Task CheckPort(IPAddress ipAddr, int port, int timeout = 3000)
        {
            log.Info($"Checking {ipAddr}:{port}");
            using (var tcpClient = new TcpClient())
            {
                var res = await tcpClient.ConnectAsync(ipAddr, port, timeout);
                PortStatus portStatus;
                switch (res.Status)
                {
                    case TaskStatus.RanToCompletion:
                        portStatus = PortStatus.OPEN;
                        break;
                    case TaskStatus.Faulted:
                        portStatus = PortStatus.CLOSED;
                        break;
                    default:
                        portStatus = PortStatus.FILTERED;
                        break;
                }

                log.Info($"Checked {ipAddr}:{port} - {portStatus}");
            }
        }
    }
}