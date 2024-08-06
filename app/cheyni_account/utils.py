import random
import string



def code_slug_generator(size=12, chars=string.digits):
    return "".join(random.choice(chars) for _ in range(size))


def create_slug_shortcode(size, model_):
    new_code = code_slug_generator(size=size)
    qs_exists = model_.objects.filter(slug=new_code).exists()
    return create_slug_shortcode(size, model_) if qs_exists else new_code


def create_transaction_shortcode(size, model_):
    new_code = code_slug_generator(size=size)
    qs_exists = model_.objects.filter(transaction=new_code).exists()
    return create_transaction_shortcode(size, model_) if qs_exists else new_code