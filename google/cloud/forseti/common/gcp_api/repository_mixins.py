# Copyright 2017 The Forseti Security Authors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Mixin classes for _base_repository.GCPRepository implementations."""

from google.cloud.forseti.common.util import logger

LOGGER = logger.get_logger(__name__)


class ListQueryMixin(object):
    """Mixin that implements paged List query."""

    def list(self, resource=None, fields=None, max_results=None, verb='list',
             **kwargs):
        """List subresources of a given resource.

        Args:
            self (GCPRespository): An instance of a GCPRespository class.
            resource (str): The id of the resource to query.
            fields (str): Fields to include in the response - partial response.
            max_results (int): Number of entries to include per page.
            verb (str): The method to call on the API.
            **kwargs (dict): Optional additional arguments to pass to the query.

        Yields:
            dict: An API response containing one page of results.
        """
        arguments = {'fields': fields,
                     self._max_results_field: max_results}

        # Most APIs call list on a parent resource to list subresources of
        # a specific type. For APIs that have no parent, set the list_key_field
        # to None when initializing the GCPRespository instance.
        if self._list_key_field and resource:
            arguments[self._list_key_field] = resource

        if kwargs:
            arguments.update(kwargs)

        if self._request_supports_pagination(verb):
            for resp in self.execute_paged_query(verb=verb,
                                                 verb_arguments=arguments):
                yield resp
        else:
            # Some API list() methods are not actually paginated.
            del arguments[self._max_results_field]
            yield self.execute_query(verb=verb, verb_arguments=arguments)


class AggregatedListQueryMixin(ListQueryMixin):
    """Mixin that implements a paged AggregatedList query."""

    def aggregated_list(self, resource=None, fields=None, max_results=None,
                        verb='aggregatedList', **kwargs):
        """List all subresource entities of a given resource.

        Args:
            self (GCPRespository): An instance of a GCPRespository class.
            resource (str): The id of the resource to query.
            fields (str): Fields to include in the response - partial response.
            max_results (int): Number of entries to include per page.
            verb (str): The method to call on the API.
            **kwargs (dict): Optional additional arguments to pass to the query.

        Returns:
            iterator: An iterator of API responses by page.
        """
        return super(AggregatedListQueryMixin, self).list(
            resource, fields, max_results, verb, **kwargs)


class GetQueryMixin(object):
    """Mixin that implements Get query."""

    def get(self, resource, target=None, fields=None, verb='get', **kwargs):
        """Get API entity.

        Args:
            self (GCPRespository): An instance of a GCPRespository class.
            resource (str): The id of the resource to query.
            target (str):  Name of the entity to fetch.
            fields (str): Fields to include in the response - partial response.
            verb (str): The method to call on the API.
            **kwargs (dict): Optional additional arguments to pass to the query.

        Returns:
            dict: Response from the API.

        Raises:
            ValueError: When get_key_field was not defined in the base
                GCPRepository instance.
            errors.HttpError: When attempting to get a non-existent entity.
               ex: HttpError 404 when requesting ... returned
                   "The resource '...' was not found"
        """
        if not self._get_key_field:
            raise ValueError('Repository was created without a valid '
                             'get_key_field argument. Cannot execute get '
                             'request.')

        arguments = {self._get_key_field: resource,
                     'fields': fields}

        # Most APIs take both a resource and a target when calling get, but
        # for APIs that the resource itself is the target, then setting
        # 'entity' to None when initializing the GCPRepository instance will
        # ensure the correct parameters are passed to the API method.
        if self._entity_field and target:
            arguments[self._entity_field] = target
        if kwargs:
            arguments.update(kwargs)
        return self.execute_query(
            verb=verb,
            verb_arguments=arguments,
        )


class GetIamPolicyQueryMixin(object):
    """Mixin that implements getIamPolicy query."""

    def get_iam_policy(self, resource, fields=None, verb='getIamPolicy',
                       include_body=True, resource_field='resource', **kwargs):
        """Get resource IAM Policy.
        Args:
            self (GCPRespository): An instance of a GCPRespository class.
            resource (str): The id of the resource to fetch.
            fields (str): Fields to include in the response - partial response.
            verb (str): The method to call on the API.
            include_body (bool): If true, include an empty body parameter in the
                method args.
            resource_field (str): The parameter name of the resource field to
                pass to the method.
            **kwargs (dict): Optional additional arguments to pass to the query.

        Returns:
            dict: Response from the API.

        Raises:
            errors.HttpError: When attempting to get a non-existent entity.
                ex: HttpError 404 when requesting ... returned
                    "The resource '...' was not found"
        """
        arguments = {resource_field: resource,
                     'fields': fields}
        if include_body:
            arguments['body'] = {}
        if kwargs:
            arguments.update(kwargs)
        return self.execute_query(
            verb=verb,
            verb_arguments=arguments,
        )


class OrgPolicyQueryMixin(object):
    """Mixin that implements getOrgPolicy and listOrgPolicies query."""

    def get_effective_org_policy(self, resource, constraint, fields=None,
                                 verb='getEffectiveOrgPolicy', **kwargs):
        """Get Effective Org Policy for a constraint on a resource.

        Args:
            self (GCPRespository): An instance of a GCPRespository class.
            resource (str): The id of the resource to fetch.
            constraint (str): The constraint name to fetch the policy for.
            fields (str): Fields to include in the response - partial response.
            verb (str): The method to call on the API.
            **kwargs (dict): Optional additional arguments to pass to the query.

        Returns:
            dict: Response from the API.

        Raises:
            errors.HttpError: When attempting to get a non-existent entity.
                ex: HttpError 404 when requesting ... returned
                    "The resource '...' was not found"
        """
        arguments = {'resource': resource, 'fields': fields,
                     'body': {'constraint': constraint}}
        if kwargs:
            arguments.update(kwargs)
        return self.execute_query(
            verb=verb,
            verb_arguments=arguments,
        )

    def get_org_policy(self, resource, constraint, fields=None,
                       verb='getOrgPolicy', **kwargs):
        """Get Org Policy for a constraint on a resource.

        Args:
            self (GCPRespository): An instance of a GCPRespository class.
            resource (str): The id of the resource to fetch.
            constraint (str): The constraint name to fetch the policy for.
            fields (str): Fields to include in the response - partial response.
            verb (str): The method to call on the API.
            **kwargs (dict): Optional additional arguments to pass to the query.

        Returns:
            dict: Response from the API.

        Raises:
            errors.HttpError: When attempting to get a non-existent entity.
                ex: HttpError 404 when requesting ... returned
                    "The resource '...' was not found"
        """
        arguments = {'resource': resource, 'fields': fields,
                     'body': {'constraint': constraint}}
        if kwargs:
            arguments.update(kwargs)
        return self.execute_query(
            verb=verb,
            verb_arguments=arguments,
        )

    def list_org_policies(self, resource, fields=None, max_results=None,
                          verb='listOrgPolicies', **kwargs):
        """List Org Policies applied to the resource.

        Args:
            self (GCPRespository): An instance of a GCPRespository class.
            resource (str): The id of the resource to query.
            fields (str): Fields to include in the response - partial response.
            max_results (int): Number of entries to include per page.
            verb (str): The method to call on the API.
            **kwargs (dict): Optional additional arguments to pass to the query.

        Yields:
            dict: An API response containing one page of results.

        Raises:
            errors.HttpError: When attempting to get a non-existent entity.
                ex: HttpError 404 when requesting ... returned
                    "The resource '...' was not found"
        """
        arguments = {'resource': resource, 'fields': fields, 'body': {}}
        if max_results:
            arguments['body']['pageSize'] = max_results

        if kwargs:
            arguments.update(kwargs)

        for resp in self.execute_search_query(
                verb=verb,
                verb_arguments=arguments):
            yield resp


class ExportAssetsQueryMixin(object):
    """Mixin that implements the exportAssets query."""

    def export_assets(self, parent, destination_object,
                      content_type=None, asset_types=None,
                      fields=None, verb='exportAssets', **kwargs):
        """Export assets under a parent resource to a file on GCS.

        Args:
            parent (str): The name of the parent resource to export assests
                under.
            destination_object (str): The GCS path and file name to store the
                results in. The bucket must be in the same project that has the
                Cloud Asset API enabled.
            content_type (str): The specific content type to export, currently
                supports "RESOURCE" and "IAM_POLICY". If not specified only the
                CAI metadata for assets are included.
            asset_types (list): The list of asset types to filter the results
                to, if not specified, exports all assets known to CAI.
            fields (str): Fields to include in the response - partial response.
            verb (str): The method to call on the API.
            **kwargs (dict): Additional parameters to pass to the API method.

        Returns:
            dict: The response from the API.
        """
        body = {
            'outputConfig': {'gcsDestination': {'uri': destination_object}}
        }
        if content_type:
            body['contentType'] = content_type

        if asset_types:
            body['assetTypes'] = asset_types

        arguments = {
            'parent': parent,
            'body': body,
            'fields': fields,
        }

        if kwargs:
            arguments.update(kwargs)

        return self.execute_query(
            verb=verb,
            verb_arguments=arguments,
        )


class SearchQueryMixin(object):
    """Mixin that implements a paged Search query."""

    def search(self, query=None, fields=None, max_results=500, verb='search'):
        """List all subresource entities visable to the caller.

        Args:
            self (GCPRespository): An instance of a GCPRespository class.
            query (str): Additional filters to apply to the restrict the
                set of resources returned.
            fields (str): Fields to include in the response - partial response.
            max_results (int): Number of entries to include per page.
            verb (str): The method to call on the API.

        Yields:
            dict: An API response containing one page of results.
        """
        req_body = {}
        if query:
            req_body[self._search_query_field] = query

        req_body[self._max_results_field] = max_results

        for resp in self.execute_search_query(
                verb=verb,
                verb_arguments={'body': req_body, 'fields': fields}):
            yield resp


class CreateQueryMixin(object):
    """Mixin that implements a Create query."""

    def create(self, verb='create', **kwargs):
        """Create a resource.

        Args:
            self (GCPRespository): An instance of a GCPRespository class.
            verb (str): The method to call on the API.
            **kwargs (dict): Optional additional arguments to pass to create.

        Returns:
            dict: An API response containing one page of results.
        """
        arguments = {}
        if kwargs.get('arguments'):
            arguments.update(kwargs.get('arguments'))

        return self.execute_query(verb=verb, verb_arguments=arguments)


class InsertResourceMixin(object):
    """Mixin that implements the Insert API command for resources."""

    def insert(self, resource, data, verb='insert', **kwargs):
        """Insert a new resource.

        Args:
            self (GCPRespository): An instance of a GCPRespository class.
            resource (str): Name of the parent resource to insert the resource
                under.
            data (dict): The json representation of the resource to add.
            verb (str): The method to call on the API.
            **kwargs (dict): Optional additional arguments to pass to the api.

        Returns:
            dict: The API response containing the async operation.

        Raises:
            ValueError: When get_key_field was not defined in the base
                GCPRepository instance.
        """
        if not self._get_key_field:
            raise ValueError('Repository was created without a valid '
                             'key_field argument. Cannot execute insert '
                             'request.')
        arguments = {
            self._get_key_field: resource,
            'body': data,
        }
        if kwargs:
            arguments.update(kwargs)

        if self.read_only:
            LOGGER.info(
                'Insert called on a read only repository, no action taken on '
                'resource %s for data %s', resource, data)
            target = data.get('name', '')
            if self._entity_field and target:
                arguments[self._entity_field] = target
            resource_link = self._build_resource_link(**arguments)
            return _create_fake_operation(resource_link, verb, target)

        return self.execute_command(verb=verb, verb_arguments=arguments)


class _ModifyResourceBaseMixin(object):
    """Base class for Patch and Update Mixins."""

    def _modify_resource(self, resource, data, target, verb, **kwargs):
        """Patch or update an existing resource.

        Args:
            self (GCPRespository): An instance of a GCPRespository class.
            resource (str): Name of the parent resource to modify the resource
                under.
            data (dict): The json representation of the resource to modify, this
                will update the existing resource.
            target (str): Name of the entity to modify.
            verb (str): The method to call on the API.
            **kwargs (dict): Optional additional arguments to pass to the api.

        Returns:
            dict: The API response containing the async operation.

        Raises:
            ValueError: When get_key_field was not defined in the base
                GCPRepository instance.
        """
        if not self._get_key_field:
            raise ValueError('Repository was created without a valid '
                             'key_field argument. Cannot execute update '
                             'request.')

        arguments = {
            self._get_key_field: resource,
            'body': data,
        }

        # Most APIs take both a resource and a target when calling update, but
        # for APIs that the resource itself is the target, then setting
        # 'entity' to None when initializing the GCPRepository instance will
        # ensure the correct parameters are passed to the API method.
        if self._entity_field and target:
            arguments[self._entity_field] = target
        if kwargs:
            arguments.update(kwargs)

        if self.read_only:
            LOGGER.info(
                '%s called on a read only repository, no action taken on '
                'target %s, resource %s for data %s.', verb, target, resource,
                data)
            resource_link = self._build_resource_link(**arguments)
            return _create_fake_operation(resource_link, verb, target)

        return self.execute_command(verb=verb, verb_arguments=arguments)


class PatchResourceMixin(_ModifyResourceBaseMixin):
    """Mixin that implements the Patch API command for resources."""

    def patch(self, resource, data, target=None, verb='patch', **kwargs):
        """Patch an existing resource.

        Args:
            self (GCPRespository): An instance of a GCPRespository class.
            resource (str): Name of the parent resource to patch the resource
                under.
            data (dict): The json representation of the resource to patch, this
                will update the existing resource.
            target (str): Name of the entity to patch.
            verb (str): The method to call on the API.
            **kwargs (dict): Optional additional arguments to pass to the api.

        Returns:
            dict: The API response containing the async operation.

        Raises:
            ValueError: When get_key_field was not defined in the base
                GCPRepository instance.
        """
        return self._modify_resource(resource, data, target, verb, **kwargs)


class UpdateResourceMixin(_ModifyResourceBaseMixin):
    """Mixin that implements the Update API command for resources."""

    def update(self, resource, data, target=None, verb='update', **kwargs):
        """Update an existing resource.

        Args:
            self (GCPRespository): An instance of a GCPRespository class.
            resource (str): Name of the parent resource to update the resource
                under.
            data (dict): The json representation of the resource to update, this
                will replace the existing resource.
            target (str): Name of the entity to update.
            verb (str): The method to call on the API.
            **kwargs (dict): Optional additional arguments to pass to the api.

        Returns:
            dict: The API response containing the async operation.

        Raises:
            ValueError: When get_key_field was not defined in the base
                GCPRepository instance.
        """
        return self._modify_resource(resource, data, target, verb, **kwargs)


class DeleteResourceMixin(object):
    """Mixin that implements the Delete API command for resources."""

    def delete(self, resource, target=None, verb='delete', **kwargs):
        """Delete an existing resource.

        Args:
            self (GCPRespository): An instance of a GCPRespository class.
            resource (str): Name of the parent resource to delete the resource
                under.
            target (str): Name of the entity to delete.
            verb (str): The method to call on the API.
            **kwargs (dict): Optional additional arguments to pass to the api.

        Returns:
            dict: The API response containing the async operation.

        Raises:
            ValueError: When get_key_field was not defined in the base
                GCPRepository instance.
        """
        if not self._get_key_field:
            raise ValueError('Repository was created without a valid '
                             'key_field argument. Cannot execute delete '
                             'request.')

        arguments = {
            self._get_key_field: resource,
        }

        # Most APIs take both a resource and a target when calling delete, but
        # for APIs that the resource itself is the target, then setting
        # 'entity' to None when initializing the GCPRepository instance will
        # ensure the correct parameters are passed to the API method.
        if self._entity_field and target:
            arguments[self._entity_field] = target
        if kwargs:
            arguments.update(kwargs)

        if self.read_only:
            LOGGER.info(
                'Delete called on a read only repository, no action taken on '
                'target %s under resource %s.', target, resource)
            resource_link = self._build_resource_link(**arguments)
            return _create_fake_operation(resource_link, verb, target)

        return self.execute_command(verb=verb, verb_arguments=arguments)


def _create_fake_operation(resource_link, verb, name):
    """Creates a fake operation resource dictionary for dry run.

    Args:
        resource_link (str): The full URL to the resource the operation would
            have modified.
        verb (str): The API method the operation would have been for.
        name (str): The operation name, can be any string.

    Returns:
        dict: A fake Operation resource.
    """
    return {
        'targetLink': resource_link,
        'operationType': verb,
        'name': name,
        'status': 'DONE',
        'progress': 100,
    }
