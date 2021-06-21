from Transforms import get_db, transform_model, transform_to_int
from numpy import array, square, sum


def plain_identification(references, sample):
    dists = []
    for template in references:
        dists.append(sum(square(array(template)-array(sample))))
    return dists

def get_identity(dists):
    return dists.index(min(dists))


if __name__ == '__main__':

    db = get_db('vgg/vgg_train_8')[:3000]
    db = transform_model(db, 'model_96')
    db, _ = transform_to_int(db, 5)
    references = [subject[0] for subject in db]

    #probe = db[1][1]
    #d = plain_identification(references, probe)

    for i in range(len(references)):
        d = plain_identification(references, db[i][-1])
        ID = get_identity(d)
        if i != ID:
            print(f'probe: {i}\t identified as: {ID}')
        if i%100 == 0:
            print(i)
