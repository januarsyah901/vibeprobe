/** Base class for every error vibeprobe raises on purpose. */
export class VibeprobeError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = new.target.name;
  }
}

/** A request was about to leave the allowed scope (host, IP, or protocol). Nothing was sent. */
export class ScopeError extends VibeprobeError {}

/** A request used an HTTP method the current mode does not allow. Nothing was sent. */
export class MethodNotAllowedError extends VibeprobeError {}

/** A redirect chain was longer than the client allows. */
export class TooManyRedirectsError extends VibeprobeError {}

/** Active mode was asked for without consent, or aimed at something that is not a local target. */
export class ActiveModeError extends VibeprobeError {}

/** The request budget for this scan is used up. Nothing more was sent. */
export class RequestBudgetError extends VibeprobeError {}
