/**
 * Copyright 2017, Google, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// TODO: figure out how to keep in sync with main repo

'use strict';

// Global
const Datastore = require('@google-cloud/datastore');
// Instantiates a client
const datastore = Datastore();
const turbiniaKind = 'TurbiniaTask';

/**
 * Retrieves tasks given a combination of start time, task
 * id, request id, or/and user or given no filter. If no
 * filter, only open Turbinia Tasks will be retrieved.
 *
 * @example
 * gcloud beta functions call gettasks \
 *    --data '{"instance": "turbinia-prod", "kind":"TurbiniaTask",
 *    "task_id":"abcd1234"}'
 *
 * @param {object} req Cloud Function request context.
 * @param {object} req.body The request body.
 * @param {string} req.body.kind The kind of Datastore Entity to request
 * @param {string} req.body.start_time A date string in ISO 8601 format of the
 *    beginning of the time window to query for
 * @param {string} req.body.task_id Id of task to retrieve
 * @param {string} req.body.request_id of tasks to retrieve
 * @param {string} req.body.user of tasks to retrieve
 * @param {object} res Cloud Function response context.
 */
exports.gettasks = function gettasks(req, res) {
  if (!req.body.instance) {
    throw new Error('Instance parameter not provided in request.');
  }
  if (!req.body.kind) {
    throw new Error('Kind parameter not provided in request.');
  }

  var query = datastore.createQuery(req.body.kind)
                  .filter('instance', '=', req.body.instance)
                  .order('last_update', {descending: true});
  var start_time;

  // Note: If you change any of these filter properties, you must also
  // update
  // the tools/gcf_init/index.yaml and re-run tools/gcf_init/deploy_gcf.py
  if (req.body.task_id) {
    console.log('Getting Turbinia Tasks by Task Id: ' + req.body.task_id);
    query = query.filter('id', '=', req.body.task_id)
  }
  if (req.body.request_id) {
    console.log('Getting Turbinia Tasks by Request Id: ' + req.body.request_id);
    query = query.filter('request_id', '=', req.body.request_id)
  }
  if (req.body.user) {
    console.log('Getting Turbinia Tasks by user: ' + req.body.user);
    query = query.filter('requester', '=', req.body.user);
  }
  if (req.body.start_time) {
    try {
      start_time = new Date(req.body.start_time)
    } catch (err) {
      throw new Error('Could not convert start_time parameter into Date object')
    }
    console.log('Getting Turbinia Tasks by last_updated range: ' + start_time);
    query = query.filter('last_update', '>=', start_time)
  }
  if (!req.body.task_id && !req.body.request_id && !req.body.user &&
      !req.start_time) {
    console.log('Getting open Turbinia Tasks.');
    query = query.filter('successful', '=', null)
  }

  console.log(query);

  return datastore.runQuery(query)
      .then((results) => {
        // Task entities found.
        const tasks = results[0];

        console.log('Turbinia Tasks:');
        tasks.forEach((task) => console.log(task));
        res.status(200).send(results);
      })
      .catch((err) => {
        console.error('Error in runQuery' + err);
        res.status(500).send(err);
        return Promise.reject(err);
      });
};

/**
 * Closes tasks based on Request ID, Task ID, or/and user.
 *
 * @example
 * gcloud beta functions call closetasks \
 *     --data '{"instance": "turbinia-prod", "kind":"TurbiniaTask",
 *              "request_id":"abcd1234"}'
 *
 * @param {object} req Cloud Function request context.
 * @param {object} req.body The request body.
 * @param {string} req.body.kind The kind of Datastore Entity to request
 * @param {string} req.body.requester The user making the request to close
 *    tasks
 * @param {string} req.body.request_id of tasks to retrieve
 * @param {string} req.body.task_id of task to retrieve
 * @param {string} req.body.user of tasks to retrieve
 * @param {object} res Cloud Function response context.
 */
exports.closetasks = function closetasks(req, res) {
  console.log(req);
  if (!req.body.instance) {
    throw new Error('Instance parameter not provided in request.');
  }
  if (!req.body.kind) {
    throw new Error('Kind parameter not provided in request.');
  }
  if (!req.body.requester) {
    throw new Error('Requester parameter not provided in request.');
  }
  if (!req.body.request_id && !req.body.task_id && !req.body.user) {
    throw new Error(
        'None of Request ID, Task ID, or user provided in request.');
  }

  var query = datastore.createQuery(req.body.kind)
                  .filter('instance', '=', req.body.instance)
                  .filter('successful', '=', null)
                  .order('last_update', {descending: true});
  if (req.body.request_id) {
    console.log('Adding filter - Request Id: ' + req.body.request_id);
    query = query.filter('request_id', '=', req.body.request_id)
  }
  if (req.body.task_id) {
    console.log('Adding filter - Task Id: ' + req.body.task_id);
    query = query.filter(
        '__key__', '=', datastore.key([turbiniaKind, req.body.task_id]))
  }
  if (req.body.user) {
    console.log('Adding filter - requester: ' + req.body.user);
    query = query.filter('requester', '=', req.body.user)
  }

  console.log(query);

  return datastore.runQuery(query)
      .then((results) => {
        // Task entities found.
        const tasks = results[0];
        var uncompleted_tasks = [];
        tasks.forEach((task) => {
          console.log(task);
          uncompleted_tasks.push(
              {'request_id': task.request_id, 'id': task.id});
        });
        return uncompleted_tasks;
      })
      .then((uncompleted_tasks) => {
        uncompleted_tasks.forEach((task) => {
          module.exports.closetask(task.id, req.body.requester);
        });
        return uncompleted_tasks;
      })
      .then((uncompleted_tasks) => { res.status(200).send(uncompleted_tasks); })
      .catch((err) => {
        console.error('Error in runQuery' + err);
        res.status(500).send(err);
        return Promise.reject(err);
      });
};

exports.closetask = function closetask(id, requester) {
  if (!id) {
    throw new Error('Task ID parameter not provided in request.');
  }
  if (!requester) {
    throw new Error('Requester parameter not provided in request.');
  }
  const transaction = datastore.transaction();
  const taskKey = datastore.key([turbiniaKind, id]);
  console.log('Preparing transaction.');
  transaction.run()
      .then(() => transaction.get(taskKey))
      .then(results => {
        const taskEntity = results[0];
        taskEntity.successful = false;
        taskEntity.status = 'Task forcefully closed by ' + requester + '.';
        var updatedEntity = {
          key: taskKey,
          data: taskEntity,
        };
        transaction.save(updatedEntity);

        console.log('Committing transaction: %o', updatedEntity);
        transaction.commit()
            .then(() => {
              console.log('Entity successfully saved.');
              return updatedEntity;
            })
            .catch(err => {
              console.error('Rolling back - Error in transaction (Failure)');
              console.error(err);
              transaction.rollback();
            });
      })
      .catch((err) => {
        console.error('Rolling back - Error in transaction (Other Reasons)');
        console.error(err);
        transaction.rollback();
      });
};