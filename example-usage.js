import trustlessGatewayFetch from './index.js'

const myblock = await trustlessGatewayFetch('bafybeiasb5vpmaounyilfuxbd3lryvosl4yefqrfahsb2esg46q6tu6y5q')

console.log('My block is: ', myblock);

const str = new TextDecoder().decode(myblock);

console.log('My block as a string: ', str);