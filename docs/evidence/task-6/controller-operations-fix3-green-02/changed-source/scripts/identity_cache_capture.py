"""One admitted in-process checkpoint capture, never approval or continuation."""
if __name__ == '__main__':
    raise SystemExit('use sole identity_cache_control entry')

def run(control):
    c = control
    pre_record, _ = c.preparation()
    c.load_modules()
    product = c.modules['identity_cache_continue']
    launch = c.launch(pre_record)
    c.deadline.arm(c.deadline.start + 80)
    module = load_api(c)
    summary = None
    code = 1
    try:
        result = product.capture_checkpoint(c.admission['writer_basis'])
        c.deadline.check(c.deadline.start + 80)
        c.deadline.arm()  # Remaining original90seconds, not a new90second interval.
        module.summary_check(result, product)
        summary = module.durable('capture-summary.json', result)
        c.records.append(summary)
        code = 0
    except Exception:
        # The in-process call returned/raised; no child can remain. Preserve any
        # checkpoint/partial summary and attempt only one failure receipt.
        c.deadline.arm()
    outcome = {'terminal': True, 'exit_code': code, 'timed_out': False, 'overflow': False}
    receipt = c.receipt(launch, outcome, None if summary is None else summary.proof())
    c.deadline.check()
    print(module.raw({'state': 'capture-returned-postflight-pending', 'receipt': receipt.proof()}).decode(),
          end='', flush=True)
    c.deadline.check()
    return code


def load_api(control):
    # Controller carries its defining module through the already-verified load.
    return control.api

