import { Resource, ResourceModel, ResourceFactory } from "./resource";

export class RemoteResource extends Resource {
  constructor(resource_model, factory) {
    super(resource_model);
    this.factory = factory;
    this.uri = `/api/${this.model.resource_id}`;
  }

  async get_data(range) {
    if (this.get_data_id() === null) {
      return [];
    }
    return await fetch(`${this.uri}/get_data`)
      .then((r) => r.blob())
      .then((b) => b.arrayBuffer());
  }

  async get_data_range_within_parent() {
    if (this.model.data_id === null) {
      return null;
    }
    const rj = await fetch(`${this.uri}/get_data_range_within_parent`, {
      cache: "force-cache",
    }).then(async (r) => {
      if (!r.ok) {
        throw Error(JSON.stringify(await r.json(), undefined, 2));
      }
      return r.json();
    });

    if (rj.length !== 2 || (0 === rj[0] && 0 === rj[1])) {
      return null;
    }

    return rj;
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
    this.factory.ingest_component_results(unpack_results);
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
    this.factory.ingest_component_results(identify_results);
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
    this.factory.ingest_component_results(unpack_recursively_results);
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
    this.factory.ingest_component_results(pack_results);
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
    this.factory.ingest_component_results(pack_results);
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
    this.factory.ingest_component_results(data_summary_results);
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
    this.factory.ingest_component_results(analyze_results);
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
    return this._remote_models_to_resources([parent_model])[0];
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
    return this._remote_models_to_resources(ancestor_models);
  }

  async get_children(r_filter, r_sort) {
    const child_models = await fetch(`${this.uri}/get_children`).then(
      async (r) => {
        if (!r.ok) {
          throw Error(JSON.stringify(await r.json(), undefined, 2));
        }
        return r.json();
      }
    );
    return this._remote_models_to_resources(child_models);
  }

  async queue_patch(patch_range, data, after, before) {
    // TODO: Implement patch_range, after, and before

    await fetch(`${this.uri}/queue_patch`, {
      method: "POST",
      body: data,
    }).then(async (r) => {
      if (!r.ok) {
        throw Error(JSON.stringify(await r.json(), undefined, 2));
      }
      return r.json();
    });
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

    this.factory.ingest_component_results(find_replace_results);
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
      this.factory.ingest_component_results(add_comment_results);
    });
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
      this.factory.ingest_component_results(delete_comment_results);
    });
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
    return this._remote_models_to_resources(matching_models);
  }

  _remote_models_to_resources(remote_models) {
    if (remote_models.length === 0) {
      return [];
    }

    const resources = [];
    for (const model of remote_models) {
      if (this.factory.model_cache[model.resource_id] === undefined) {
        this.factory.add_to_cache(model);
      }
      resources.push(this.factory.create(model.id));
    }
    return resources;
  }
}

function remote_model_to_js_model(remote_model) {
  const attrs = {};

  for (const [attr_t, info] of remote_model.attributes) {
    attrs[attr_t] = info[1];
  }

  return new ResourceModel(
    remote_model.id,
    remote_model.data_id,
    remote_model.parent_id,
    remote_model.tags,
    remote_model.caption,
    attrs
  );
}

export class RemoteResourceFactory extends ResourceFactory {
  constructor() {
    super();

    this.model_cache = {};
  }

  create(resource_id) {
    return new RemoteResource(this.model_cache[resource_id], this);
  }

  add_to_cache(remote_model) {
    this.model_cache[remote_model.id] = remote_model_to_js_model(remote_model);
  }

  update_in_cache(remote_model) {
    const existing_model = this.model_cache[remote_model.id];
    const new_attrs = {};

    for (const [attr_t, info] of remote_model.attributes) {
      new_attrs[attr_t] = info[1];
    }
    existing_model.resource_id = remote_model.id;
    existing_model.data_id = remote_model.data_id;
    existing_model.parent_id = remote_model.parent_id;
    existing_model.tags = remote_model.tags;
    existing_model.caption = remote_model.caption;
    existing_model.attributes = new_attrs;
  }

  ingest_component_results(results) {
    for (const new_model of results["created"]) {
      this.add_to_cache(new_model);
    }
    for (const modified_model of results["modified"]) {
      this.update_in_cache(modified_model);
    }
    for (const deleted_id of results["deleted"]) {
      delete this.model_cache[deleted_id];
    }
  }
}
