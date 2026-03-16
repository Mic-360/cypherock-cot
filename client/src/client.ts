// tcp conn manager for cot-mta client. 

// linking up w/ the cpp server. uses promises n 4-byte big-endian length prefixes

import * as net from 'net';

export class Client {
  private socket: net.Socket;
  private readonly host: string;
  private readonly port: number;
  private receiveBuffer: Buffer = Buffer.alloc(0);
  private pendingResolve: ((data: Buffer) => void) | null = null;
  private pendingReject: ((err: Error) => void) | null = null;

  constructor(host: string, port: number) {
    this.host = host;
    this.port = port;
    this.socket = new net.Socket();
  }

  // connect to server. returns promise
  async connect(): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      this.socket.connect(this.port, this.host, () => {
        resolve();
      });

      this.socket.on('error', (err) => {
        if (this.pendingReject) {
          this.pendingReject(err);
          this.pendingResolve = null;
          this.pendingReject = null;
        } else {
          reject(err);
        }
      });

      this.socket.on('data', (chunk: Buffer) => {
        this.receiveBuffer = Buffer.concat([this.receiveBuffer, chunk]);
        this.tryDeliverMessage();
      });

      this.socket.on('close', () => {
        if (this.pendingReject) {
          this.pendingReject(new Error('Connection closed'));
          this.pendingResolve = null;
          this.pendingReject = null;
        }
      });
    });
  }

  // a framed msg (4-byte prefix included)
  sendMessage(data: Buffer): void {
    this.socket.write(data);
  }

  // catch exactly 1 length-prefixed protobuf msg.
  async receiveMessage(): Promise<Buffer> {
    return new Promise<Buffer>((resolve, reject) => {
      this.pendingResolve = resolve;
      this.pendingReject = reject;
      // checking if we got a full msg in buffer already
      this.tryDeliverMessage();
    });
  }

  /**
   * check if buffer actually has a full msg n deliver it if it does
   */
  private tryDeliverMessage(): void {
    if (!this.pendingResolve) return;
    if (this.receiveBuffer.length < 4) return;

    const messageLength = this.receiveBuffer.readUInt32BE(0);
    if (this.receiveBuffer.length < 4 + messageLength) return;

    const messageData = Buffer.from(
      this.receiveBuffer.subarray(4, 4 + messageLength)
    );
    this.receiveBuffer = Buffer.from(
      this.receiveBuffer.subarray(4 + messageLength)
    );

    const resolve = this.pendingResolve;
    this.pendingResolve = null;
    this.pendingReject = null;
    resolve(messageData);
  }

  /**
   * nuke the tcp conn
   */
  disconnect(): void {
    this.socket.destroy();
  }
}
