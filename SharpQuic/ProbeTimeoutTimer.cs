using System;
using System.Diagnostics;
using System.Threading.Tasks;

namespace SharpQuic;

public sealed class ProbeTimeoutTimer {
    readonly QuicConnection connection;

    readonly PacketWriter packetWriter;

    internal ProbeTimeoutTimer(QuicConnection connection) {
        this.connection = connection;
        packetWriter = new(connection);
    }

    public Task StartAsync() {
        return Task.Factory.StartNew(Runner, TaskCreationOptions.LongRunning);
    }

    async Task Runner() {
        try {
            long min = 0;

            while(!connection.connectionSource.IsCancellationRequested) {
                long next = Math.Min(connection.initialStage?.ProbeTimeout ?? long.MaxValue, Math.Min(connection.handshakeStage?.ProbeTimeout ?? long.MaxValue, connection.applicationStage?.ProbeTimeout ?? long.MaxValue));

                Console.WriteLine($"Initial: {connection.initialStage?.ProbeTimeout}. Handshake: {connection.handshakeStage?.ProbeTimeout}. Application: {connection.applicationStage?.ProbeTimeout}");
                Console.WriteLine($"Min: {min}. Next: {next}");

                if(next <= min) {
                    Console.WriteLine("Probe");

                    if(connection.initialStage?.ProbeTimeout <= min)
                        connection.initialStage.WriteProbe(packetWriter);

                    if(connection.handshakeStage?.ProbeTimeout <= min)
                        connection.handshakeStage.WriteProbe(packetWriter);

                    if(connection.applicationStage?.ProbeTimeout <= min)
                        connection.applicationStage.WriteProbe(packetWriter);

                    await connection.SendAsync(packetWriter);
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
