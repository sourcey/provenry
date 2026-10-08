import {
  type DefaultTreeAdapterMap,
  Parser,
  type ParserOptions,
  type Token,
  Tokenizer,
  type TokenizerOptions,
} from "parse5";

/** A run of appends longer than this leaves the native string for gathered pieces. */
const SPILL_LENGTH = 1_024;
/** Spilled runs joined into one flat piece, so unjoined runs hold at most about a megabyte. */
const RUNS_PER_PIECE = 32;

/**
 * parse5 builds attribute values and character runs (an inline script) by appending one code
 * point at a time. Appended in place, megabytes of it become a rope with one heap node per
 * character: 7 MB of base64 held 222 MB, a 3 MB script 96 MB. Short runs stay native strings;
 * a long one spills into flat pieces and stays its own size.
 */
class SpilledText {
  readonly #pieces: string[] = [];
  readonly #runs: string[] = [];

  get holding(): boolean {
    return this.#pieces.length > 0 || this.#runs.length > 0;
  }

  spill(run: string): void {
    this.#runs.push(run);
    if (this.#runs.length === RUNS_PER_PIECE) {
      this.#pieces.push(this.#runs.join(""));
      this.#runs.length = 0;
    }
  }

  /** The spilled text followed by `tail`, leaving nothing spilled. */
  take(tail: string): string {
    const text = this.#pieces.join("") + this.#runs.join("") + tail;
    this.#pieces.length = 0;
    this.#runs.length = 0;
    return text;
  }
}

/** The tokenizer only appends to a value (`+=`); it reads back the short native tail. */
class GatheredAttribute {
  #tail = "";
  readonly #spilled = new SpilledText();

  constructor(public name: string) {}

  get value(): string {
    return this.#tail;
  }

  set value(text: string) {
    if (text.length < SPILL_LENGTH) {
      this.#tail = text;
    } else {
      this.#spilled.spill(text);
      this.#tail = "";
    }
  }

  settle(): Token.Attribute {
    return {
      name: this.name,
      value: this.#spilled.holding ? this.#spilled.take(this.#tail) : this.#tail,
    };
  }
}

/** parse5's tokenizer, handing the tree builder the same plain tokens it builds itself. */
class GatheringTokenizer extends Tokenizer {
  readonly #spilledCharacters = new SpilledText();

  protected override _createAttr(attrNameFirstCh: string): void {
    super._createAttr(attrNameFirstCh);
    this.currentAttr = new GatheredAttribute(attrNameFirstCh) as unknown as Token.Attribute;
  }

  protected override emitCurrentTagToken(): void {
    const token = this.currentToken as Token.TagToken;
    token.attrs = token.attrs.map((attribute) =>
      attribute instanceof GatheredAttribute ? attribute.settle() : attribute,
    );
    super.emitCurrentTagToken();
  }

  protected override _appendCharToCurrentCharacterToken(
    type: Token.CharacterToken["type"],
    ch: string,
  ): void {
    super._appendCharToCurrentCharacterToken(type, ch);
    const token = this.currentCharacterToken as Token.CharacterToken;
    if (token.chars.length >= SPILL_LENGTH) {
      this.#spilledCharacters.spill(token.chars);
      token.chars = "";
    }
  }

  protected override _emitCurrentCharacterToken(nextLocation: Token.Location | null): void {
    if (this.currentCharacterToken && this.#spilledCharacters.holding) {
      this.currentCharacterToken.chars = this.#spilledCharacters.take(
        this.currentCharacterToken.chars,
      );
    }
    super._emitCurrentCharacterToken(nextLocation);
  }
}

class GatheringParser extends Parser<DefaultTreeAdapterMap> {
  constructor(options?: ParserOptions<DefaultTreeAdapterMap>) {
    super(options);
    const tokenizer = new GatheringTokenizer(this.options as TokenizerOptions, this);
    tokenizer.inForeignNode = this.tokenizer.inForeignNode;
    this.tokenizer = tokenizer;
  }
}

/** A node and an element of parse5's tree, for readers of a parsed page. */
export type HtmlNode = DefaultTreeAdapterMap["node"];
export type HtmlElement = DefaultTreeAdapterMap["element"];

/** parse5's document tree for HTML, with long attribute values and text held at their size. */
export function parseHtmlDocument(html: string): DefaultTreeAdapterMap["document"] {
  return GatheringParser.parse(html) as DefaultTreeAdapterMap["document"];
}
