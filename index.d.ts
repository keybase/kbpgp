declare module "kbpgp" {

  interface KeyManager {
    get_ekid: () => Buffer;
  }

  namespace verify {
    type Kid = string;
    interface GenericKey {
      kid: () => Kid;
      isPGP: () => boolean;
      verify: (s: string) => Promise<Buffer>;
    }

    function importKey(s: string): Promise<GenericKey>;
  }

  namespace kb {
    function unbox(
      arg: { armored: string } | { binary: Buffer },
      cb: (
        err: Error | null,
        res: { payload: Buffer; km: KeyManager } | null
      ) => void
    ): void;
    function verify(
      arg: { armored: string; kid: string } | { binary: Buffer; kid: string },
      cb: (err: Error | null, paload: Buffer | null) => void
    ): void;
  }
}
