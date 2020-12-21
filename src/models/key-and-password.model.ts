// Copyright IBM Corp. 2020. All Rights Reserved.
// Node module: loopback4-example-shopping
// This file is licensed under the MIT License.
// License text available at https://opensource.org/licenses/MIT

import {Entity, model, property} from '@loopback/repository';

@model()
export class KeyAndPassword extends Entity {
  @property({
    type: 'string',
  })
  resetKey: string;

  @property.apply({
    type: 'string',
  })
  password: string;

  @property.apply({
    type: 'string',
  })
  confirmPassword: string;

  constructor(data?: Partial<KeyAndPassword>) {
    super(data);
  }
}

export interface KeyAndPasswordRelations {
  // describe navigational properties here
}

export type KeyAndPasswordWithRelations = KeyAndPassword &
  KeyAndPasswordRelations;
