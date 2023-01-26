import { Resource } from "./resource";

let batchQueues = {};

function createQueue(route, maxlen) {
  batchQueues[route] = {
    maxlen: maxlen != undefined ? maxlen : 1024,
    requests: [],
    responses: {},
    timeout: null,
    getResults: async (requests) => {
      const queue = batchQueues[route];
      if (!requests) {
        requests = queue.requests;
        queue.requests = [];
      }

      const result_models = await fetch(`/batch/${route}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(requests),
      }).then(async (r) => {
        if (!r.ok) {
          throw Error(JSON.stringify(await r.json(), undefined, 2));
        }
        return await r.json();
      });

      for (const [child_id, result_model] of Object.entries(result_models)) {
        if (!queue.responses[child_id]) {
          // This should only happen in two cases:
          // 1. The server responds with IDs we didn't ask for
          // 2. batchedCall was called with this ID twice, and an earlier batch
          //    resolved all of the responses for this ID already
          continue;
        }
        queue.responses[child_id].forEach((callback) => callback(result_model));
        delete queue.responses[child_id];
      }
    },
  };
}

async function batchedCall(resource, route, maxlen) {
  if (!batchQueues[route]) {
    createQueue(route, maxlen);
  }
  const queue = batchQueues[route];

  clearTimeout(queue.timeout);
  queue.requests.push(resource.resource_id);
  if (!queue.responses[resource.resource_id]) {
    queue.responses[resource.resource_id] = [];
  }
  let result = new Promise((resolve) => {
    queue.responses[resource.resource_id].push(resolve);
  });

  if (queue.requests.length > queue.maxlen) {
    const requestsCopy = queue.requests;
    queue.requests = [];
    await queue.getResults(requestsCopy);
  } else {
    queue.timeout = setTimeout(queue.getResults, 100);
  }

  return await result;
}

export class RemoteResource extends Resource {
  constructor(
    resource_id,
    data_id,
    parent_id,
    tags,
    caption,
    attributes,
    resource_list
  ) {
    super(resource_id, data_id, parent_id, tags, caption, attributes);

    this.resource_list = resource_list;
    this.uri = `/${this.resource_id}`;
    this.cache = {
      get_children: undefined,
      get_data_range_within_parent: undefined,
      get_data: undefined,
    };
  }

  async flush_cache() {
    Object.keys(this.cache).forEach((k) => {
      this.cache[k] = undefined;
    });
  }

  update() {
    const newer = this.resource_list[this.resource_id];
    this.tags = newer.tags;
    this.caption = newer.caption;
    this.attributes = newer.attributes;
  }

  async get_children(r_filter, r_sort) {
    if (this.cache["get_children"]) {
      return remote_models_to_resources(
        this.cache["get_children"],
        this.resource_list
      );
    }

    const model = await batchedCall(this, "get_children");
    this.cache["get_children"] = model;

    return remote_models_to_resources(model, this.resource_list);
  }

  async get_data(range) {
    if (this.data_id === null) {
      return [];
    }

    if (this.cache["get_data"]) {
      return this.cache["get_data"];
    }
    let result = await fetch(`${this.uri}/get_data`)
      .then((r) => r.blob())
      .then((b) => b.arrayBuffer());
    this.cache["get_data"] = result;
    return result;
  }

  async get_data_range_within_parent() {
    if (this.data_id === null) {
      return null;
    }
    let rj;
    if (this.cache["get_data_range_within_parent"]) {
      rj = this.cache["get_data_range_within_parent"];
    } else {
      rj = await batchedCall(this, "get_data_range_within_parent", 1024);
      this.cache["get_data_range_within_parent"] = rj;
    }
    if (rj.length !== 2 || (0 === rj[0] && 0 === rj[1])) {
      return null;
    }
    return rj;
  }

  async get_child_data_ranges() {
    if (this.cache["get_data_range_within_parent"]) {
      return this.cache["get_data_range_within_parent"];
    }

    let result = await fetch(`${this.uri}/get_child_data_ranges`).then((r) =>
      r.json()
    );
    this.cache["get_data_range_within_parent"] = result;
    return result;
  }

  async unpack() {
    const unpack_results = await fetch(`${this.uri}/unpack`, {
      method: "POST",
    }).then(async (r) => {
      if (!r.ok) {
        throw Error(JSON.stringify(await r.json(), undefined, 2));
      }
      return r.json();
    });
    ingest_component_results(unpack_results, this.resource_list);
    this.flush_cache();
    this.update();
  }

  async identify() {
    const identify_results = await fetch(`${this.uri}/identify`, {
      method: "POST",
    }).then(async (r) => {
      if (!r.ok) {
        throw Error(JSON.stringify(await r.json(), undefined, 2));
      }
      return r.json();
    });
    ingest_component_results(identify_results, this.resource_list);
    this.update();
  }

  async unpack_recursively() {
    const unpack_recursively_results = await fetch(
      `${this.uri}/unpack_recursively`,
      { method: "POST" }
    ).then(async (r) => {
      if (!r.ok) {
        throw Error(JSON.stringify(await r.json(), undefined, 2));
      }
      return r.json();
    });
    ingest_component_results(unpack_recursively_results, this.resource_list);
    this.flush_cache();
    this.update();
  }

  async pack() {
    const pack_results = await fetch(`${this.uri}/pack`, {
      method: "POST",
    }).then(async (r) => {
      if (!r.ok) {
        throw Error(JSON.stringify(await r.json(), undefined, 2));
      }
      return r.json();
    });
    ingest_component_results(pack_results, this.resource_list);
    this.flush_cache();
    this.update();
  }

  async pack_recursively() {
    const pack_results = await fetch(`${this.uri}/pack_recursively`, {
      method: "POST",
    }).then(async (r) => {
      if (!r.ok) {
        throw Error(JSON.stringify(await r.json(), undefined, 2));
      }
      return r.json();
    });
    ingest_component_results(pack_results, this.resource_list);
    this.flush_cache();
    this.update();
  }

  async data_summary() {
    const data_summary_results = await fetch(`${this.uri}/data_summary`, {
      method: "POST",
    }).then(async (r) => {
      if (!r.ok) {
        throw Error(JSON.stringify(await r.json(), undefined, 2));
      }
      return r.json();
    });
    ingest_component_results(data_summary_results, this.resource_list);
    this.update();
  }

  async analyze() {
    const analyze_results = await fetch(`${this.uri}/analyze`, {
      method: "POST",
    }).then(async (r) => {
      if (!r.ok) {
        throw Error(JSON.stringify(await r.json(), undefined, 2));
      }
      return r.json();
    });
    ingest_component_results(analyze_results, this.resource_list);
    this.flush_cache();
    this.update();
  }

  async get_parent() {
    const parent_model = await fetch(`${this.uri}/get_parent`).then(
      async (r) => {
        if (!r.ok) {
          throw Error(JSON.stringify(await r.json(), undefined, 2));
        }
        return r.json();
      }
    );
    return remote_model_to_resource(parent_model);
  }

  async get_ancestors(r_filter) {
    const ancestor_models = await fetch(`${this.uri}/get_ancestors`).then(
      async (r) => {
        if (!r.ok) {
          throw Error(JSON.stringify(await r.json(), undefined, 2));
        }
        return r.json();
      }
    );
    return remote_models_to_resources(ancestor_models);
  }

  async queue_patch(data, start, end, after, before) {
    // TODO: Implement after and before

    start = start || 0;
    end = end || 0;
    const patch_results = await fetch(
      `${this.uri}/queue_patch?start=${start}&end=${end}`,
      {
        method: "POST",
        body: data,
      }
    ).then(async (r) => {
      if (!r.ok) {
        throw Error(JSON.stringify(await r.json(), undefined, 2));
      }
      return r.json();
    });
    this.flush_cache();
  }

  async create_child(
    tags,
    attributes,
    data,
    data_range,
    data_after,
    data_before
  ) {
    // TODO: Implement tags, attributes, data, data_after, data_before

    await fetch(`${this.uri}/create_mapped_child`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(data_range),
    }).then(async (r) => {
      if (!r.ok) {
        throw Error(JSON.stringify(await r.json(), undefined, 2));
      }
      return await r.json();
    });
    this.cache["get_children"] = undefined;
  }

  async find_and_replace(
    to_find,
    replace_with,
    null_terminate,
    allow_overflow
  ) {
    const find_replace_results = await fetch(`${this.uri}/find_and_replace`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify([
        "ofrak.core.strings.StringFindReplaceConfig",
        {
          to_find: to_find,
          replace_with: replace_with,
          null_terminate: null_terminate,
          allow_overflow: allow_overflow,
        },
      ]),
    }).then(async (r) => {
      if (!r.ok) {
        throw Error(JSON.stringify(await r.json(), undefined, 2));
      }
      return await r.json();
    });

    ingest_component_results(find_replace_results, this.resource_list);
    this.flush_cache();
    this.update();
  }

  async add_comment(optional_range, comment) {
    await fetch(`${this.uri}/add_comment`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify([optional_range, comment]),
    }).then(async (r) => {
      if (!r.ok) {
        throw Error(JSON.stringify(await r.json(), undefined, 2));
      }
      const add_comment_results = await r.json();
      ingest_component_results(add_comment_results, this.resource_list);
    });
    this.flush_cache();
    this.update();
  }

  async delete_comment(optional_range) {
    await fetch(`${this.uri}/delete_comment`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(optional_range),
    }).then(async (r) => {
      if (!r.ok) {
        throw Error(JSON.stringify(await r.json(), undefined, 2));
      }
      const delete_comment_results = await r.json();
      ingest_component_results(delete_comment_results, this.resource_list);
    });
    this.flush_cache();
    this.update();
  }

  async search_for_vaddr(vaddr_start, vaddr_end) {
    const matching_models = await fetch(`${this.uri}/search_for_vaddr`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify([vaddr_start, vaddr_end]),
    }).then(async (r) => {
      if (!r.ok) {
        throw Error(JSON.stringify(await r.json(), undefined, 2));
      }
      return await r.json();
    });
    return remote_models_to_resources(matching_models);
  }
}

export function remote_models_to_resources(remote_models, resources) {
  return Array.from(remote_models).map((m) =>
    remote_model_to_resource(m, resources)
  );
}

export function remote_model_to_resource(remote_model, resources) {
  const attrs = {};
  for (const [attr_t, info] of remote_model.attributes) {
    attrs[attr_t] = info[1];
  }
  const result = new RemoteResource(
    remote_model.id,
    remote_model.data_id,
    remote_model.parent_id,
    remote_model.tags,
    remote_model.caption,
    attrs,
    resources
  );

  if (resources) {
    resources[remote_model.id] = result;
  }

  return result;
}

function ingest_component_results(results, resources) {
  remote_models_to_resources(results["created"], resources);
  remote_models_to_resources(results["modified"], resources);
  for (const deleted_id of results["deleted"]) {
    delete resources[deleted_id];
  }
}
