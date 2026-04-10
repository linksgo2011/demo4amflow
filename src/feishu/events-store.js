const { randomUUID } = require('node:crypto');

function createEventsStore({ max = 200 } = {}) {
  const items = [];

  function push(event) {
    items.unshift({
      id: randomUUID(),
      ts: new Date().toISOString(),
      ...event,
    });
    if (items.length > max) items.length = max;
  }

  function list() {
    return items.slice();
  }

  function clear() {
    items.length = 0;
  }

  return { push, list, clear };
}

module.exports = { createEventsStore };

