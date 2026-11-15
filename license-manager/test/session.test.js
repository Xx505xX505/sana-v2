import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import vm from "node:vm";
import { fileURLToPath } from "node:url";

class Element {
  constructor() {
    this.children = [];
    this.listeners = new Map();
    this.value = "";
    this.textContent = "";
    this.className = "";
  }
  addEventListener(name, callback) { this.listeners.set(name, callback); }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = [...children]; }
}

async function loadManager() {
  const elements = new Map();
  const getElement = id => {
    if (!elements.has(id)) elements.set(id, new Element());
    return elements.get(id);
  };
  const windowListeners = new Map();
  const source = await readFile(fileURLToPath(new URL("../manager.js", import.meta.url)), "utf8");
  vm.runInNewContext(source, {
    document: { getElementById: getElement, createElement: () => new Element() },
    window: { addEventListener: (name, callback) => windowListeners.set(name, callback) },
    localStorage: { getItem: () => null, setItem() {}, removeItem() {} },
    URL,
    AbortSignal,
    fetch: async () => { throw new Error("Network should not be used in session-clear tests"); },
    confirm: () => true,
    prompt: () => "test",
    navigator: { clipboard: { writeText: async () => {} } },
    console
  }, { filename: "manager.js" });
  return { elements, getElement, windowListeners };
}

test("disconnect clears issued keys only when the administrator ends the session", async () => {
  const { elements, getElement } = await loadManager();
  const issued = getElement("issued");
  issued.replaceChildren(new Element(), new Element());
  assert.equal(issued.children.length, 2, "Keys remain available to copy during the active session.");

  await elements.get("disconnect").listeners.get("click")();

  assert.equal(issued.children.length, 0);
});

test("ending the app session clears issued keys from the rendered page", async () => {
  const { getElement, windowListeners } = await loadManager();
  const issued = getElement("issued");
  issued.replaceChildren(new Element());

  windowListeners.get("pagehide")();

  assert.equal(issued.children.length, 0);
});
