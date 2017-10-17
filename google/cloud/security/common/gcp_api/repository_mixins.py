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
