declare module "kbpgp" {
  class BaseX {
    public base: number
    constructor(alphabet: string)
    encode(input: Buffer): string
    decode(input: string): Buffer
  }
  export const base58: BaseX
  export const base32: BaseX
  export const base91: BaseX

  namespace util {
    function json_stringify_sorted(o: any): string;
  }

  interface KeyManager {
    get_ekid: () => Buffer;
  }

  namespace ukm {
    function get_sig_body(arg: { armored: string }): [Error|null,Buffer];
  }

  namespace verify {
    type Kid = string;
    interface GenericKey {
      kid: () => Kid;
      isPGP: () => boolean;
      verify: (s: string, opts?: Opts) => Promise<[Buffer, Buffer]>;
    }

    type Opts = {
      time_travel?: boolean;
      now?: number;
      no_check_keys?: boolean;
    };

    function importKey(s: string, opts?: Opts): Promise<GenericKey>;
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
