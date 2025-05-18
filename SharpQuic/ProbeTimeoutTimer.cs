using System;
using System.Diagnostics;
using System.Threading.Tasks;

namespace SharpQuic;

public sealed class ProbeTimeoutTimer {
    readonly QuicConnection connection;

    internal ProbeTimeoutTimer(QuicConnection connection) {
        this.connection = connection;
    }

    public Task StartAsync() {
        return Task.Factory.StartNew(Runner, TaskCreationOptions.LongRunning);
    }

    async Task Runner() {
        try {
            long min = 0;

            while(true) {
                long next = Math.Min(connection.initialStage?.ProbeTimeout ?? long.MaxValue, Math.Min(connection.handshakeStage?.ProbeTimeout ?? long.MaxValue, connection.applicationStage?.ProbeTimeout ?? long.MaxValue));

                Console.WriteLine($"Initial: {connection.initialStage?.ProbeTimeout}. Handshake: {connection.handshakeStage?.ProbeTimeout}. Application: {connection.applicationStage?.ProbeTimeout}");
                Console.WriteLine($"Min: {min}. Next: {next}");

                if(next <= min) {
                    Console.WriteLine("Probe");

                    if(connection.initialStage?.ProbeTimeout <= min)
                        await connection.initialStage.SendProbe();

                    if(connection.handshakeStage?.ProbeTimeout <= min)
                        await connection.handshakeStage.SendProbe();

                    if(connection.applicationStage?.ProbeTimeout <= min)
                        await connection.applicationStage.SendProbe();
                } else {
                    int time = (int)(next - Stopwatch.GetTimestamp() * 1000 / Stopwatch.Frequency);

                    Console.WriteLine($"Sleeping {time}");

                    if(time > 0)
                        await Task.Delay(time);

                    Console.WriteLine("Timer");
                }

                min = next;
            }
        } catch(Exception e) {
            Console.WriteLine(e);
        }
    }
}
