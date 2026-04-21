declare namespace chrome {
  namespace tabs {
    interface Tab {
      id?: number;
      url?: string;
      title?: string;
      active?: boolean;
    }

    function query(
      queryInfo: { active?: boolean; currentWindow?: boolean },
      callback: (tabs: Tab[]) => void
    ): void;
  }

  namespace cookies {
    type SameSiteStatus = "no_restriction" | "lax" | "strict" | "unspecified";

    interface Cookie {
      name: string;
      value: string;
      domain: string;
      path: string;
      expirationDate?: number;
      secure: boolean;
      httpOnly: boolean;
      sameSite?: SameSiteStatus;
      session: boolean;
      hostOnly?: boolean;
      storeId: string;
    }

    function getAll(details: { domain?: string; url?: string }, callback: (cookies: Cookie[]) => void): void;
  }

  namespace downloads {
    function download(options: {
      url: string;
      filename?: string;
      saveAs?: boolean;
      conflictAction?: "uniquify" | "overwrite" | "prompt";
    }): Promise<number>;
  }

  namespace runtime {
    interface MessageSender {
      tab?: tabs.Tab;
    }

    interface MessageSenderResponse {
      ok: boolean;
      error?: string;
    }

    interface RuntimeMessageEvent {
      addListener(
        callback: (
          message: unknown,
          sender: MessageSender,
          sendResponse: (response?: MessageSenderResponse) => void
        ) => boolean | void
      ): void;
    }

    const lastError: { message?: string } | undefined;
    const onMessage: RuntimeMessageEvent;

    function sendMessage(message: unknown): Promise<MessageSenderResponse | undefined>;
  }
}
