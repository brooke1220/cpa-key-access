'use strict';
// Minimal DOM stand-in so web/settings.js can be smoke-tested without jsdom or network access.
function textOf(node) {
  if (node.nodeType === 3) return node.text;
  return node.children.map(textOf).join('');
}

class TextNode {
  constructor(text) { this.nodeType = 3; this.text = text; }
}

class El {
  constructor(tag) {
    this.nodeType = 1;
    this.tag = tag;
    this.children = [];
    this.attrs = {};
    this.listeners = {};
    this.className = '';
    this.disabled = false;
    this._value = undefined;
  }
  setAttribute(name, value) {
    this.attrs[name] = String(value);
    if (name === 'disabled') this.disabled = true;
  }
  addEventListener(type, fn) { (this.listeners[type] = this.listeners[type] || []).push(fn); }
  append(...kids) { for (const kid of kids) this.children.push(typeof kid === 'string' ? new TextNode(kid) : kid); }
  replaceChildren(...kids) { this.children = []; this.append(...kids); }
  get id() { return this.attrs.id || ''; }
  get value() {
    if (this._value !== undefined) return this._value;
    return this.tag === 'textarea' ? textOf(this) : this.attrs.value || '';
  }
  set value(v) { this._value = v; }
  set textContent(v) { this.children = [new TextNode(String(v))]; }
}

function findAll(node, pred, out = []) {
  if (pred(node)) out.push(node);
  for (const child of node.children || []) findAll(child, pred, out);
  return out;
}

function fire(node, type, extra) {
  for (const fn of node.listeners[type] || []) fn(Object.assign({ target: node }, extra));
}

function makeDocument() {
  const app = new El('main');
  app.attrs.id = 'app';
  return {
    app,
    createElement: (tag) => new El(tag),
    getElementById: (id) => findAll(app, (n) => n.nodeType === 1 && n.id === id)[0] || null,
  };
}

module.exports = { textOf, findAll, fire, makeDocument };
