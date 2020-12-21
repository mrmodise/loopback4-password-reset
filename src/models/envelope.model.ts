// Copyright IBM Corp. 2020. All Rights Reserved.
// Node module: loopback4-example-shopping
// This file is licensed under the MIT License.
// License text available at https://opensource.org/licenses/MIT

import {Entity, model, property} from '@loopback/repository';

@model()
export class Envelope extends Entity {
  @property({
    type: 'string',
  })
  from: string;

  @property.apply({
    type: 'string',
  })
  to: string;

  constructor(data?: Partial<Envelope>) {
    super(data);
  }
}

export interface EnvelopeRelations {
  // describe navigational properties here
}

export type EnvelopeWithRelations = Envelope & EnvelopeRelations;
