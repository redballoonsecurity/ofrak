export class ResourceModel {
  constructor(resource_id, data_id, parent_id, tags, caption, attributes) {
    this.resource_id = resource_id;
    this.data_id = data_id;
    this.parent_id = parent_id;
    this.tags = tags;
    this.caption = caption;
    this.attributes = attributes;
  }
}

function NotImplementedError(unimplementedMethodName) {
  this.unimplementedMethodName = unimplementedMethodName;
  this.toString = () => `${this.unimplementedMethodName} not implemented`;
}

export class Resource {
  constructor(model) {
    this.model = model;
  }

  get_id() {
    return this.model.resource_id;
  }

  async get_job_id() {
    // Sync in ResourceInterface
    throw new NotImplementedError("get_job_id");
  }

  get_data_id() {
    return this.model.data_id;
  }

  async get_resource_context() {
    // Sync in ResourceInterface
    throw new NotImplementedError("get_resource_context");
  }

  async get_resource_view_context() {
    // Sync in ResourceInterface
    throw new NotImplementedError("get_resource_view_context");
  }

  async get_component_context() {
    // Sync in ResourceInterface
    throw new NotImplementedError("get_component_context");
  }

  async get_job_context() {
    // Sync in ResourceInterface
    throw new NotImplementedError("get_job_context");
  }

  async is_modified() {
    // Sync in ResourceInterface
    throw new NotImplementedError("is_modified");
  }

  async get_model() {
    // Sync in ResourceInterface
    throw new NotImplementedError("get_model");
  }

  async get_data(range) {
    if (this.get_data_id() === null) {
      return [];
    }

    throw new NotImplementedError("get_data");
  }

  async get_data_length() {
    throw new NotImplementedError("get_data_length");
  }

  async get_data_index_within_parent() {
    throw new NotImplementedError("get_data_index_within_parent");
  }

  async get_data_range_within_parent() {
    throw new NotImplementedError("get_data_range_within_parent");
  }

  async get_data_range_within_root() {
    throw new NotImplementedError("get_data_range_within_root");
  }

  async get_offset_within_root() {
    throw new NotImplementedError("get_offset_within_root");
  }

  async get_data_unmapped_range(offset) {
    throw new NotImplementedError("get_data_unmapped_range");
  }

  async set_data_alignment(alignment) {
    throw new NotImplementedError("set_data_alignment");
  }

  async set_data_overlaps_enabled(enable_overlaps) {
    throw new NotImplementedError("set_data_overlaps_enabled");
  }

  async save() {
    throw new NotImplementedError("save");
  }

  async fetch() {
    throw new NotImplementedError("fetch");
  }

  async run(component_type, config) {
    throw new NotImplementedError("run");
  }

  async auto_run(
    components,
    blacklisted_components,
    all_unpackers,
    all_identifiers,
    all_analyzers
  ) {
    throw new NotImplementedError("auto_run");
  }

  async unpack() {
    throw new NotImplementedError("unpack");
  }

  async analyze(resource_attributes) {
    throw new NotImplementedError("analyze");
  }

  async identify() {
    throw new NotImplementedError("identify");
  }

  async pack() {
    throw new NotImplementedError("pack");
  }

  async auto_run_recursively(
    components,
    blacklisted_components,
    blacklisted_tags,
    all_unpackers,
    all_identifiers,
    all_analyzers
  ) {
    throw new NotImplementedError("auto_run_recursively");
  }

  async unpack_recursively(blacklisted_components, do_not_unpack) {
    throw new NotImplementedError("unpack_recursively");
  }

  async analyze_recursively() {
    throw new NotImplementedError("analyze_recursively");
  }

  async pack_recursively() {
    throw new NotImplementedError("pack_recursively");
  }

  async write_to(destination) {
    throw new NotImplementedError("write_to");
  }

  async create_child(
    tags,
    attributes,
    data,
    data_range,
    data_after,
    data_before
  ) {
    throw new NotImplementedError("create_child");
  }

  async create_child_from_view(
    view,
    data_range,
    data,
    additional_tags,
    additional_attributes
  ) {
    throw new NotImplementedError("create_child_from_view");
  }

  async view_as(viewable_tag) {
    throw new NotImplementedError("view_as");
  }

  async add_view(view) {
    // Sync in ResourceInterface
    throw new NotImplementedError("add_view");
  }

  async add_tag(tags) {
    // Sync in ResourceInterface
    throw new NotImplementedError("add_tag");
  }

  get_tags(inherit) {
    return this.model.tags;
  }

  get_caption(inherit) {
    return this.model.caption;
  }

  async get_related_tags(tag) {
    // Sync in ResourceInterface
    throw new NotImplementedError("get_related_tags");
  }

  has_tag(tag, inherit) {
    return this.model.tags.includes(tag);
  }

  async remove_tag(tag) {
    // Sync in ResourceInterface
    throw new NotImplementedError("remove_tag");
  }

  async analyze_attributes(attributes_type) {
    throw new NotImplementedError("analyze_attributes");
  }

  async add_attributes(attributes) {
    // Sync in ResourceInterface
    throw new NotImplementedError("add_attributes");
  }

  get_attributes(attributes_type) {
    // Sync in ResourceInterface
    return this.model.attributes;
  }

  async get_all_attributes() {
    // Sync in ResourceInterface
    throw new NotImplementedError("get_all_attributes");
  }

  async has_attributes(attributes_type) {
    // Sync in ResourceInterface
    throw new NotImplementedError("has_attributes");
  }

  async remove_attributes(attributes_type) {
    // Sync in ResourceInterface
    throw new NotImplementedError("remove_attributes");
  }

  async add_component(component_id, version) {
    // Sync in ResourceInterface
    throw new NotImplementedError("add_component");
  }

  async add_component_for_attributes(component_id, version, attributes) {
    // Sync in ResourceInterface
    throw new NotImplementedError("add_component_for_attributes");
  }

  async remove_component(component_id, attributes) {
    // Sync in ResourceInterface
    throw new NotImplementedError("remove_component");
  }

  async has_component_run(component_id, desired_version) {
    // Sync in ResourceInterface
    throw new NotImplementedError("has_component_run");
  }

  async move(dest_range, after, before) {
    // Sync in ResourceInterface
    throw new NotImplementedError("move");
  }

  async queue_patch(patch_range, data, after, before) {
    // Sync in ResourceInterface
    throw new NotImplementedError("queue_patch");
  }

  async get_parent_as_view(v_type) {
    throw new NotImplementedError("get_parent_as_view");
  }

  async get_parent() {
    throw new NotImplementedError("get_parent");
  }

  async get_ancestors(r_filter) {
    throw new NotImplementedError("get_ancestors");
  }

  async get_only_ancestor_as_view(v_type, r_filter) {
    throw new NotImplementedError("get_only_ancestor_as_view");
  }

  async get_only_ancestor(r_filter) {
    throw new NotImplementedError("get_only_ancestor");
  }

  async get_descendants_as_view(v_type, max_depth, r_filter, r_sort) {
    throw new NotImplementedError("get_descendants_as_view");
  }

  async get_descendants(max_depth, r_filter, r_sort) {
    throw new NotImplementedError("get_descendants");
  }

  async get_only_descendant_as_view(v_type, max_depth, r_filter) {
    throw new NotImplementedError("get_only_descendant_as_view");
  }

  async get_only_descendant(max_depth, r_filter) {
    throw new NotImplementedError("get_only_descendant");
  }

  async get_siblings_as_view(v_type, r_filter, r_sort) {
    throw new NotImplementedError("get_siblings_as_view");
  }

  async get_siblings(r_filter, r_sort) {
    throw new NotImplementedError("get_siblings");
  }

  async get_only_sibling_as_view(v_type, r_filter) {
    throw new NotImplementedError("get_only_sibling_as_view");
  }

  async get_only_sibling(r_filter) {
    throw new NotImplementedError("get_only_sibling");
  }

  async get_children_as_view(v_type, r_filter, r_sort) {
    throw new NotImplementedError("get_children_as_view");
  }

  async get_children(r_filter, r_sort) {
    throw new NotImplementedError("get_children");
  }

  async get_only_child_as_view(v_type, r_filter) {
    throw new NotImplementedError("get_only_child_as_view");
  }

  async get_only_child(r_filter) {
    throw new NotImplementedError("get_only_child");
  }

  async delete() {
    throw new NotImplementedError("delete");
  }

  async flush_to_disk(path) {
    throw new NotImplementedError("flush_to_disk");
  }

  async summarize() {
    throw new NotImplementedError("summarize");
  }

  async summarize_tree(r_filter, r_sort) {
    throw new NotImplementedError("summarize_tree");
  }

  async add_comment(optional_range, comment) {
    throw new NotImplementedError("add_comment");
  }

  async delete_comment(optional_range) {
    throw new NotImplementedError("delete_comment");
  }

  async get_comments() {
    let attributes = this.get_attributes();
    if ("ofrak.core.comments.CommentsAttributes" in attributes) {
      return attributes["ofrak.core.comments.CommentsAttributes"]["comments"];
    } else {
      return [];
    }
  }

  async search_for_vaddr(vaddr_start, vaddr_end) {
    throw new NotImplementedError("search_for_vaddr");
  }

  /***
   * Return the string representation of a comment, which includes its range as prefix if it
   * has one.
   */
  async prettify_comment(comment) {
    let range_prefix = "";
    if (comment[0] !== null) {
      let startOffset = comment[0][0];
      let endOffset = comment[0][1];
      // TODO get the data length without calling get_data
      let data = await this.get_data();
      if (startOffset !== 0 || endOffset !== data.byteLength) {
        let startOffset_hex = `0x${startOffset.toString(16)}`;
        let endOffset_hex = `0x${endOffset.toString(16)}`;
        range_prefix = "(" + startOffset_hex + "-" + endOffset_hex + ") ";
      }
    }
    return range_prefix + comment[1];
  }
}

export class ResourceFactory {
  create(resource_id) {}
}

export class RemoteResourceFactory extends ResourceFactory {
  // Incomplete class, placeholder for later
  constructor(resource_service) {
    super();
    this.resource_service = resource_service;
  }

  create(resource_id) {
    // TODO: Fetch the resource model from this.resource_service
    const resource_model = null;
    return new Resource(resource_model);
  }
}
